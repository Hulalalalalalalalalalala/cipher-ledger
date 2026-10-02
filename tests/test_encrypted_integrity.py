"""Contract tests for GET /v1/encrypted-records/integrity.

The endpoint runs a tenant-scoped consistency inspection over the sealed
batches, records, append events and idempotency bindings. Success shape and
counts, the high-water mark, error precedence (403 before anything, 503
before 422), cross-tenant association detection in both directions, orphan
rows, whole-batch and stored-shape re-validation, serial visibility under
concurrent commits, restart and key-rotation stability, and read-only
behaviour are all exercised here; tampering is performed directly on the
SQLite file.
"""

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import Config
from cipher_ledger.database import connect
from cipher_ledger.server import LedgerServer

KEY_MATERIAL = {v: bytes([v]) * 16 + bytes([100 + v]) * 16 for v in (1, 2, 3)}
INGEST_PATH = "/v1/encrypted-records/batch"
INTEGRITY_PATH = "/v1/encrypted-records/integrity"
OK_KEYS = {"status", "batch_count", "record_count", "event_count",
           "binding_count", "high_water"}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def make_config(directory: Path, active: int = 1) -> Config:
    return Config(directory / "ledger.sqlite3", active, dict(KEY_MATERIAL))


class ServerHarness:
    def __init__(self, config: Config):
        self.server = LedgerServer(("127.0.0.1", 0), config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def sealed_record(record_id, algorithm="AES-256-GCM"):
    wrapped_len = 48 if algorithm == "AES-256-GCM" else 32
    return {
        "id": record_id,
        "algorithm": algorithm,
        "key_id": "client-key-1",
        "envelope": {
            "nonce": b64(os.urandom(12)),
            "wrapped_key": b64(os.urandom(wrapped_len)),
        },
        "ciphertext": {
            "data": b64(b"encrypted body " + record_id.encode()),
            "nonce": b64(os.urandom(12)),
            "tag": b64(os.urandom(16)),
        },
        "metadata": {"source": "test"},
    }


class EncryptedIntegrityTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant="acme", headers=None):
        sent_headers = {}
        if tenant is not None:
            sent_headers["X-Tenant-ID"] = tenant
        if headers:
            sent_headers.update(headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.harness.base + path, data=data, headers=sent_headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def integrity(self, query="", tenant="acme"):
        path = INTEGRITY_PATH if not query else INTEGRITY_PATH + "?" + query
        return self.request("GET", path, tenant=tenant)

    def ingest(self, count=1, tenant="acme", key=None, records=None):
        if records is None:
            records = [
                sealed_record(f"{tenant}-{os.urandom(8).hex()}-{i}") for i in range(count)
            ]
        headers = {"Idempotency-Key": key} if key is not None else None
        return self.request(
            "POST", INGEST_PATH, {"records": records}, tenant=tenant, headers=headers
        )

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def tamper(self, sql, params=()):
        raw = self.db()
        try:
            with raw:
                raw.execute(sql, params)
        finally:
            raw.close()

    def tenant_batch_ids(self, tenant="acme"):
        raw = self.db()
        try:
            rows = raw.execute(
                "SELECT batch_id FROM encrypted_batches WHERE tenant=? ORDER BY batch_id",
                (tenant,),
            ).fetchall()
            return [row[0] for row in rows]
        finally:
            raw.close()

    def max_seq(self, tenant="acme"):
        raw = self.db()
        try:
            row = raw.execute(
                "SELECT MAX(seq) FROM encrypted_record_events WHERE tenant=?", (tenant,)
            ).fetchone()
            return row[0] or 0
        finally:
            raw.close()

    # -- success shape and counts -------------------------------------------

    def test_empty_tenant_is_ok_with_all_zeros(self):
        status, body = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(set(body), OK_KEYS)
        self.assertEqual(
            body,
            {
                "status": "ok",
                "batch_count": 0,
                "record_count": 0,
                "event_count": 0,
                "binding_count": 0,
                "high_water": 0,
            },
        )

    def test_counts_and_high_water_reflect_committed_state(self):
        self.assertEqual(self.ingest(2)[0], 201)
        self.assertEqual(self.ingest(3, key="key-one")[0], 201)
        self.assertEqual(self.ingest(1, tenant="other", key="key-two")[0], 201)
        status, body = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(set(body), OK_KEYS)
        self.assertEqual(
            body,
            {
                "status": "ok",
                "batch_count": 2,
                "record_count": 5,
                "event_count": 5,
                "binding_count": 1,
                "high_water": self.max_seq(),
            },
        )
        # The other tenant sees only its own totals.
        self.assertEqual(
            self.integrity(tenant="other"),
            (
                200,
                {
                    "status": "ok",
                    "batch_count": 1,
                    "record_count": 1,
                    "event_count": 1,
                    "binding_count": 1,
                    "high_water": self.max_seq("other"),
                },
            ),
        )

    def test_query_parameters_are_ignored(self):
        self.ingest(1)
        expected = self.integrity()
        for query in ("limit=1", "cursor=whatever", "after_seq=99", "x=&y"):
            with self.subTest(query=query):
                self.assertEqual(self.integrity(query), expected)

    def test_plaintext_records_and_snapshots_are_out_of_scope(self):
        self.request("POST", "/v1/records", {"id": "plain-1", "plaintext": "secret"})
        self.request("POST", "/v1/records/batch", {
            "records": [{"id": f"plain-{i}", "plaintext": "x"} for i in range(2, 6)]
        })
        # A multi-page batch listing leaves persisted snapshot rows behind.
        self.ingest(3)
        self.ingest(1)
        status, page = self.request("GET", "/v1/encrypted-records/batches?limit=1")
        self.assertEqual(status, 200)
        self.assertIn("next_cursor", page)
        self.assertEqual(
            self.integrity(),
            (
                200,
                {
                    "status": "ok",
                    "batch_count": 2,
                    "record_count": 4,
                    "event_count": 4,
                    "binding_count": 0,
                    "high_water": self.max_seq(),
                },
            ),
        )

    def test_failed_commits_and_replays_do_not_change_counts(self):
        records = [sealed_record("rec-a"), sealed_record("rec-b")]
        self.assertEqual(self.ingest(records=records, key="key-one")[0], 201)
        before = self.integrity()
        # Same key, same content: replayed 200, nothing written.
        self.assertEqual(self.ingest(records=records, key="key-one")[0], 200)
        # Same key, different content: 409 conflict, nothing written.
        self.assertEqual(self.ingest(records=[sealed_record("rec-c")], key="key-one")[0], 409)
        # Existing ids with a fresh key: 400, nothing written.
        self.assertEqual(self.ingest(records=records, key="key-two")[0], 400)
        # Malformed batch: 400, nothing written.
        self.assertEqual(self.ingest(records=[{"id": "broken"}])[0], 400)
        self.assertEqual(self.integrity(), before)

    def test_key_rotation_does_not_change_result(self):
        self.ingest(2, key="key-one")
        before = self.integrity()
        self.assertEqual(
            self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200
        )
        self.assertEqual(self.integrity(), before)

    def test_restart_keeps_checking_existing_data(self):
        self.ingest(2, key="key-one")
        self.ingest(1)
        before = self.integrity()
        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.assertEqual(self.integrity(), before)

    def test_serial_visibility_under_concurrent_commits(self):
        errors = []

        def commit_batches():
            try:
                for _ in range(5):
                    status, _ = self.ingest(2)
                    if status != 201:
                        errors.append(status)
            except Exception as exc:  # pragma: no cover - failure detail
                errors.append(exc)

        threads = [threading.Thread(target=commit_batches) for _ in range(4)]
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads):
            status, body = self.integrity()
            self.assertEqual(status, 200)
            # Every observation is one complete serial state: one event per
            # record, and the water mark covers every visible event.
            self.assertEqual(body["record_count"], body["event_count"])
            self.assertGreaterEqual(body["high_water"], body["event_count"])
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        status, body = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(body["batch_count"], 20)
        self.assertEqual(body["record_count"], 40)
        self.assertEqual(body["event_count"], 40)

    # -- tenant authorization -------------------------------------------------

    def test_missing_or_invalid_tenant_is_forbidden(self):
        self.ingest(1)
        for tenant in (None, "bad tenant!", "a/b", "", "x" * 65):
            with self.subTest(tenant=tenant):
                self.assertEqual(
                    self.integrity(tenant=tenant),
                    (403, {"error": "TENANT_RECORD_FORBIDDEN"}),
                )
                # The 403 wins over any query parameter as well.
                self.assertEqual(
                    self.integrity("limit=0", tenant=tenant),
                    (403, {"error": "TENANT_RECORD_FORBIDDEN"}),
                )

    # -- storage failures -----------------------------------------------------

    def test_storage_failure_is_503_bare_error(self):
        for table in (
            "encrypted_batches",
            "encrypted_records",
            "encrypted_record_events",
            "encrypted_batch_idempotency_keys",
        ):
            with self.subTest(table=table):
                self.ingest(1, key="key-one")
                self.tamper("DROP TABLE %s" % table)
                self.assertEqual(self.integrity(), (503, {"error": "storage_error"}))
                # Reset to a fresh database for the next case.
                self.harness.close()
                for leftover in self.directory.glob("ledger.sqlite3*"):
                    leftover.unlink()
                self.harness = ServerHarness(make_config(self.directory))

    def test_storage_failure_takes_precedence_over_corruption(self):
        self.ingest(2)
        # Corrupt the record side, then make the event read fail: the 503
        # must win because every read happens before any review.
        self.tamper("DELETE FROM encrypted_records")
        self.tamper("DROP TABLE encrypted_record_events")
        self.assertEqual(self.integrity(), (503, {"error": "storage_error"}))

    # -- integrity failures ---------------------------------------------------

    def expect_integrity_error(self):
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_missing_record_is_422(self):
        self.ingest(2)
        self.tamper(
            "DELETE FROM encrypted_records WHERE tenant='acme' AND position=0"
        )
        self.expect_integrity_error()

    def test_missing_event_is_422(self):
        self.ingest(2)
        self.tamper(
            "DELETE FROM encrypted_record_events WHERE tenant='acme' AND position=1"
        )
        self.expect_integrity_error()

    def test_orphan_record_is_422(self):
        self.ingest(1)
        record = sealed_record("ghost")
        self.tamper(
            "INSERT INTO encrypted_records "
            "(tenant, id, batch_id, position, algorithm, encryption_key_id, "
            "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata) "
            "VALUES ('acme', 'ghost', ?, 0, 'AES-256-GCM', NULL, ?, ?, ?, ?, ?, NULL)",
            (
                "batch_" + "0" * 32,
                base64.b64decode(record["envelope"]["nonce"]),
                base64.b64decode(record["envelope"]["wrapped_key"]),
                base64.b64decode(record["ciphertext"]["data"]),
                base64.b64decode(record["ciphertext"]["nonce"]),
                base64.b64decode(record["ciphertext"]["tag"]),
            ),
        )
        self.expect_integrity_error()

    def test_orphan_event_is_422(self):
        self.ingest(1)
        self.tamper(
            "INSERT INTO encrypted_record_events (batch_id, tenant, record_id, position) "
            "VALUES (?, 'acme', 'ghost', 0)",
            ("batch_" + "1" * 32,),
        )
        self.expect_integrity_error()

    def test_orphan_binding_is_422(self):
        self.ingest(1)
        self.tamper(
            "INSERT INTO encrypted_batch_idempotency_keys "
            "(tenant, idempotency_key, batch_id, created_at) "
            "VALUES ('acme', 'dangling', ?, '2026-01-01T00:00:00+00:00')",
            ("batch_" + "2" * 32,),
        )
        self.expect_integrity_error()

    def test_foreign_record_pointing_at_tenant_batch_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_batch_ids()[0]
        record = sealed_record("intruder")
        self.tamper(
            "INSERT INTO encrypted_records "
            "(tenant, id, batch_id, position, algorithm, encryption_key_id, "
            "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata) "
            "VALUES ('other', 'intruder', ?, 1, 'AES-256-GCM', NULL, ?, ?, ?, ?, ?, NULL)",
            (
                batch_id,
                base64.b64decode(record["envelope"]["nonce"]),
                base64.b64decode(record["envelope"]["wrapped_key"]),
                base64.b64decode(record["ciphertext"]["data"]),
                base64.b64decode(record["ciphertext"]["nonce"]),
                base64.b64decode(record["ciphertext"]["tag"]),
            ),
        )
        self.expect_integrity_error()

    def test_foreign_event_pointing_at_tenant_batch_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_batch_ids()[0]
        self.tamper(
            "INSERT INTO encrypted_record_events (batch_id, tenant, record_id, position) "
            "VALUES (?, 'other', 'intruder', 0)",
            (batch_id,),
        )
        self.expect_integrity_error()

    def test_foreign_binding_pointing_at_tenant_batch_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_batch_ids()[0]
        self.tamper(
            "INSERT INTO encrypted_batch_idempotency_keys "
            "(tenant, idempotency_key, batch_id, created_at) "
            "VALUES ('other', 'stolen', ?, '2026-01-01T00:00:00+00:00')",
            (batch_id,),
        )
        self.expect_integrity_error()

    def test_tenant_record_repointed_at_foreign_batch_is_422(self):
        self.ingest(1)
        self.ingest(1, tenant="other")
        foreign_batch = self.tenant_batch_ids("other")[0]
        self.tamper(
            "UPDATE encrypted_records SET batch_id=? WHERE tenant='acme'",
            (foreign_batch,),
        )
        self.expect_integrity_error()

    def test_malformed_batch_id_is_422(self):
        self.ingest(1, key="key-one")
        batch_id = self.tenant_batch_ids()[0]
        for table, column in (
            ("encrypted_records", "batch_id"),
            ("encrypted_record_events", "batch_id"),
            ("encrypted_batch_idempotency_keys", "batch_id"),
        ):
            self.tamper(
                "UPDATE %s SET %s='not-a-batch' WHERE batch_id=?" % (table, column),
                (batch_id,),
            )
        self.tamper(
            "UPDATE encrypted_batches SET batch_id='not-a-batch' WHERE batch_id=?",
            (batch_id,),
        )
        self.expect_integrity_error()

    def test_event_seq_out_of_range_is_422(self):
        self.ingest(1)
        self.tamper("UPDATE encrypted_record_events SET seq=0 WHERE tenant='acme'")
        self.expect_integrity_error()

    def test_binding_key_shape_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_batch_ids()[0]
        raw = self.db()
        try:
            created_at = raw.execute(
                "SELECT created_at FROM encrypted_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()[0]
        finally:
            raw.close()
        self.tamper(
            "INSERT INTO encrypted_batch_idempotency_keys "
            "(tenant, idempotency_key, batch_id, created_at) "
            "VALUES ('acme', 'bad key!', ?, ?)",
            (batch_id, created_at),
        )
        self.expect_integrity_error()

    def test_binding_timestamp_drift_is_422(self):
        self.ingest(1, key="key-one")
        self.tamper(
            "UPDATE encrypted_batch_idempotency_keys "
            "SET created_at='2026-01-01T00:00:00+00:00' WHERE tenant='acme'"
        )
        self.expect_integrity_error()

    def test_record_position_swap_is_422(self):
        self.ingest(2)
        self.tamper(
            "UPDATE encrypted_records SET position=1-position WHERE tenant='acme'"
        )
        self.expect_integrity_error()

    def test_stored_record_shape_drift_is_422(self):
        self.ingest(1)
        self.tamper(
            "UPDATE encrypted_records SET algorithm='AES-192-GCM' WHERE tenant='acme'"
        )
        self.expect_integrity_error()

    def test_equal_length_ciphertext_change_still_passes(self):
        records = [sealed_record("rec-a")]
        self.ingest(records=records)
        original = base64.b64decode(records[0]["ciphertext"]["data"])
        flipped = bytes([original[0] ^ 1]) + original[1:]
        self.tamper(
            "UPDATE encrypted_records SET ciphertext=? WHERE tenant='acme'",
            (flipped,),
        )
        # The inspection never decrypts or authenticates client ciphertext.
        self.assertEqual(self.integrity()[0], 200)

    def test_other_tenant_corruption_does_not_affect_result(self):
        self.ingest(2, key="key-one")
        self.ingest(1, tenant="other")
        before = self.integrity()
        # Destroy the other tenant's only batch and its plain records table
        # rows; this tenant's verdict and counts are unchanged.
        self.tamper("DELETE FROM encrypted_record_events WHERE tenant='other'")
        self.tamper("DELETE FROM encrypted_batches WHERE tenant='other'")
        self.assertEqual(self.integrity(), before)
        # The other tenant itself now fails its own inspection.
        self.assertEqual(
            self.integrity(tenant="other"), (422, {"error": "integrity_error"})
        )

    def test_batch_without_binding_is_legal(self):
        # Batches committed without an Idempotency-Key (or before idempotency
        # existed) simply have no binding row.
        self.ingest(2)
        status, body = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(body["binding_count"], 0)


if __name__ == "__main__":
    unittest.main()
