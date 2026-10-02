"""Contract tests for GET /v1/encrypted-records/integrity.

The endpoint is a read-only, tenant-wide consistency inspection over the
sealed-batch protocol tables. These tests cover the success shape (exact six
fields, zeros for an empty tenant), totals and high water from one serial
state, the 403 tenant-header precedence, every cross-tenant/orphan/shape
drift that must fail with a bare 422, 503 storage precedence over
corruption, tenant isolation, read-only/replay/rollback behaviour, restart
and rotation stability and serial visibility under concurrency. Most
tampering is performed directly on the SQLite file.
"""

import copy
import json
import os
import shutil
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
IDEMPOTENCY_TABLE = "encrypted_batch_idempotency_keys"


def b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


def make_config(directory: Path, active: int = 1) -> Config:
    return Config(directory / "ledger.sqlite3", active, dict(KEY_MATERIAL))


class ServerHarness:
    def __init__(self, config: Config):
        self.server = LedgerServer(("127.0.0.1", 0), config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[0], self.server.server_port
        self.base = f"http://{self.host}:{self.port}"
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def sealed_record(record_id, algorithm="AES-256-GCM", **overrides):
    wrapped_len = 48 if algorithm == "AES-256-GCM" else 32
    record = {
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
    record.update(overrides)
    return record


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    # -- transport helpers -------------------------------------------------

    def ingest(self, records, key=None, tenant="acme"):
        headers = {"Content-Type": "application/json", "X-Tenant-ID": tenant}
        if key is not None:
            headers["Idempotency-Key"] = key
        data = json.dumps({"records": records}).encode("utf-8")
        request = urllib.request.Request(
            self.harness.base + INGEST_PATH, data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def integrity(self, tenant="acme", suffix=""):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        request = urllib.request.Request(
            self.harness.base + INTEGRITY_PATH + suffix, headers=headers
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def create_plain_record(self, record_id, tenant="acme"):
        # A server-encrypted ordinary record, which the inspection must ignore.
        data = json.dumps({"id": record_id, "plaintext": "ordinary"}).encode("utf-8")
        request = urllib.request.Request(
            self.harness.base + "/v1/records",
            data=data,
            headers={"Content-Type": "application/json", "X-Tenant-ID": tenant},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            return response.status

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def tamper(self, statement, params=()):
        raw = self.db()
        try:
            with raw:
                raw.execute(statement, params)
        finally:
            raw.close()

    # -- success shape ------------------------------------------------------

    def test_tenant_without_sealed_data_reports_all_zero(self):
        status, report = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(
            report,
            {
                "status": "ok",
                "batch_count": 0,
                "record_count": 0,
                "event_count": 0,
                "binding_count": 0,
                "high_water": 0,
            },
        )
        # Exactly the six specified fields -- no envelope, batch id or detail.
        self.assertEqual(
            set(report),
            {
                "status",
                "batch_count",
                "record_count",
                "event_count",
                "binding_count",
                "high_water",
            },
        )

    def test_counts_and_water_over_keyed_and_keyless_batches(self):
        _, first = self.ingest(
            [sealed_record("a1"), sealed_record("a2")], key="k-1"
        )
        self.ingest([sealed_record("b1")])  # historical, no idempotency binding
        _, third = self.ingest(
            [sealed_record("c1"), sealed_record("c2"), sealed_record("c3")],
            key="k-2",
        )
        status, report = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["batch_count"], 3)
        self.assertEqual(report["record_count"], 6)
        self.assertEqual(report["event_count"], 6)
        self.assertEqual(report["binding_count"], 2)
        # Only this tenant commits, so its seqs are 1..6 and the water is 6.
        self.assertEqual(report["high_water"], 6)
        self.assertTrue(first["batch_id"] and third["batch_id"])

    def test_water_ignores_gaps_and_other_tenants(self):
        self.ingest([sealed_record("a1")], tenant="acme")
        self.ingest([sealed_record("b1")], tenant="beta")
        self.ingest([sealed_record("b2")], tenant="beta")
        self.ingest([sealed_record("a2")], tenant="acme")
        status, acme = self.integrity(tenant="acme")
        self.assertEqual(status, 200)
        # Acme owns seqs 1 and 4: gaps are legitimate and the water is its max.
        self.assertEqual(acme["event_count"], 2)
        self.assertEqual(acme["record_count"], 2)
        self.assertEqual(acme["high_water"], 4)
        status, beta = self.integrity(tenant="beta")
        self.assertEqual(status, 200)
        self.assertEqual(beta["event_count"], 2)
        self.assertEqual(beta["high_water"], 3)

    def test_query_parameters_are_ignored(self):
        self.ingest([sealed_record("a1")], key="k-1")
        for suffix in ("?limit=999", "?cursor=bogus&x=y", "?", "?=&&="):
            with self.subTest(suffix=suffix):
                status, report = self.integrity(suffix=suffix)
                self.assertEqual(status, 200)
                self.assertEqual(report["batch_count"], 1)

    def test_server_encrypted_records_and_other_tenants_are_not_counted(self):
        self.create_plain_record("plain-1")
        self.ingest([sealed_record("a1")], key="k-1", tenant="beta")
        status, report = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(
            report,
            {
                "status": "ok",
                "batch_count": 0,
                "record_count": 0,
                "event_count": 0,
                "binding_count": 0,
                "high_water": 0,
            },
        )

    # -- tenant header precedence ------------------------------------------

    def test_missing_or_invalid_tenant_is_403_before_anything_else(self):
        self.ingest([sealed_record("a1")], key="k-1")
        for tenant in (None, "", "bad tenant!", "x" * 65):
            for suffix in ("", "?limit=1", "?anything"):
                with self.subTest(tenant=tenant, suffix=suffix):
                    status, body = self.integrity(tenant=tenant, suffix=suffix)
                    self.assertEqual((status, body), (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    # -- integrity failures: 422 -------------------------------------------

    def test_batch_count_drift_is_422(self):
        _, created = self.ingest([sealed_record("a1"), sealed_record("a2")], key="k-1")
        self.tamper(
            "UPDATE encrypted_batches SET record_count=1 WHERE batch_id=?",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_missing_event_is_422(self):
        _, created = self.ingest([sealed_record("a1"), sealed_record("a2")])
        self.tamper(
            "DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_missing_record_is_422(self):
        _, created = self.ingest([sealed_record("a1"), sealed_record("a2")])
        self.tamper(
            "DELETE FROM encrypted_records WHERE batch_id=? AND position=1",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_orphan_records_and_events_after_batch_delete_are_422(self):
        _, created = self.ingest([sealed_record("a1")], key="k-1")
        # Delete only the batch header: its records, events and binding dangle.
        self.tamper(
            "DELETE FROM encrypted_batches WHERE batch_id=?",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_record_repointed_at_other_tenant_is_422(self):
        _, created = self.ingest([sealed_record("a1"), sealed_record("a2")])
        self.tamper(
            "UPDATE encrypted_records SET tenant='other' "
            "WHERE batch_id=? AND position=0",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_event_repointed_at_other_tenant_is_422(self):
        _, created = self.ingest([sealed_record("a1")])
        self.tamper(
            "UPDATE encrypted_record_events SET tenant='other' WHERE batch_id=?",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_foreign_record_linked_into_this_tenants_batch_is_422(self):
        # An own-tenant record dangling at a foreign batch id is an orphan;
        # here a row carrying another tenant lands on this tenant's batch.
        _, acme = self.ingest([sealed_record("a1")], tenant="acme")
        self.ingest([sealed_record("b1")], tenant="beta")
        # Beta's record now claims acme's batch: a cross-tenant association
        # that acme's inspection must surface even though the row's tenant
        # column is not acme.
        self.tamper(
            "UPDATE encrypted_records SET batch_id=? WHERE id='b1'",
            (acme["batch_id"],),
        )
        self.assertEqual(self.integrity(tenant="acme"), (422, {"error": "integrity_error"}))

    def test_foreign_binding_linked_into_this_tenants_batch_is_422(self):
        _, acme = self.ingest([sealed_record("a1")], key="k-1", tenant="acme")
        raw = self.db()
        with raw:
            raw.execute(
                f"INSERT INTO {IDEMPOTENCY_TABLE} "
                "(tenant, idempotency_key, batch_id, created_at) "
                "VALUES ('gamma', 'gk', ?, ?)",
                (acme["batch_id"], "2026-10-02T08:30:00+00:00"),
            )
        raw.close()
        # Acme's review loads the foreign binding because it points at acme's
        # batch; the cross-tenant link fails it.
        self.assertEqual(self.integrity(tenant="acme"), (422, {"error": "integrity_error"}))

    def test_own_binding_repointed_at_other_tenants_batch_is_422(self):
        self.ingest([sealed_record("a1")], key="k-1", tenant="acme")
        _, beta = self.ingest([sealed_record("b1")], key="k-1", tenant="beta")
        self.tamper(
            f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
            "WHERE tenant='acme' AND idempotency_key='k-1'",
            (beta["batch_id"],),
        )
        # Acme fails: its binding dangles outside its own batches.
        self.assertEqual(self.integrity(tenant="acme"), (422, {"error": "integrity_error"}))
        # Beta fails too: its sweep includes every binding directly pointing at
        # beta's batches, and acme's repointed binding is a cross-tenant link.
        self.assertEqual(self.integrity(tenant="beta"), (422, {"error": "integrity_error"}))

    def test_malformed_batch_id_on_batch_record_event_or_binding_is_422(self):
        _, created = self.ingest([sealed_record("a1")], key="k-1")
        bad_batch_ids = ("bogus", "batch_" + "0" * 31, "batch_" + "G" * 32, "")
        for bad in bad_batch_ids:
            with self.subTest(bad=bad):
                self.tamper(
                    f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                    "WHERE tenant='acme' AND idempotency_key='k-1'",
                    (bad,),
                )
                self.assertEqual(
                    self.integrity(), (422, {"error": "integrity_error"})
                )
        # Restore the binding, then plant a standalone malformed batch header.
        self.tamper(
            f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
            "WHERE tenant='acme' AND idempotency_key='k-1'",
            (created["batch_id"],),
        )
        raw = self.db()
        with raw:
            raw.execute(
                "INSERT INTO encrypted_batches "
                "(batch_id, tenant, record_count, created_at) "
                "VALUES ('bogus', 'acme', 1, '2026-10-02T08:30:00+00:00')"
            )
        raw.close()
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_binding_key_and_timestamp_drift_are_422(self):
        _, created = self.ingest([sealed_record("a1")], key="k-1")
        tamperings = [
            (
                f"UPDATE {IDEMPOTENCY_TABLE} SET idempotency_key='bad key!' "
                "WHERE batch_id=?",
                (created["batch_id"],),
            ),
            (
                f"UPDATE {IDEMPOTENCY_TABLE} SET idempotency_key=? "
                "WHERE batch_id=?",
                ("x" * 65, created["batch_id"]),
            ),
            (
                f"UPDATE {IDEMPOTENCY_TABLE} SET created_at='1999-01-01T00:00:00+00:00' "
                "WHERE batch_id=?",
                (created["batch_id"],),
            ),
        ]
        for statement, params in tamperings:
            with self.subTest(statement=statement):
                self.tamper(statement, params)
                self.assertEqual(
                    self.integrity(), (422, {"error": "integrity_error"})
                )

    def test_non_string_binding_timestamp_is_422(self):
        self.ingest([sealed_record("a1")], key="k-1")
        self.tamper(
            f"UPDATE {IDEMPOTENCY_TABLE} SET created_at=x'07' "
            "WHERE tenant='acme' AND idempotency_key='k-1'"
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_event_sequence_zero_or_negative_is_422(self):
        # UPDATE can assign a non-positive rowid even though INSERT could not;
        # both violate the 1..2^63-1 sequence rule (gaps, by contrast, pass).
        for bad in (0, -1):
            with self.subTest(bad=bad):
                _, created = self.ingest([sealed_record(f"a{bad}")])
                self.tamper(
                    "UPDATE encrypted_record_events SET seq=? WHERE batch_id=?",
                    (bad, created["batch_id"]),
                )
                self.assertEqual(
                    self.integrity(), (422, {"error": "integrity_error"})
                )

    def test_record_shape_drift_is_422(self):
        _, created = self.ingest([sealed_record("a1")])
        self.tamper(
            "UPDATE encrypted_records SET algorithm='AES-192-GCM' WHERE batch_id=?",
            (created["batch_id"],),
        )
        self.assertEqual(self.integrity(), (422, {"error": "integrity_error"}))

    def test_equal_length_ciphertext_change_still_passes(self):
        _, created = self.ingest([sealed_record("a1")], key="k-1")
        # The inspection never opens envelopes: a same-length byte change to
        # the ciphertext is shape-valid and must not fail the review.
        self.tamper(
            "UPDATE encrypted_records SET ciphertext=? "
            "WHERE batch_id=? AND position=0",
            (b"x" * len(b"encrypted body a1"), created["batch_id"]),
        )
        status, report = self.integrity()
        self.assertEqual(status, 200)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["record_count"], 1)

    # -- storage failures: 503 ---------------------------------------------

    def test_sqlite_read_failures_are_503(self):
        # Each table gets its own seeded database, so one drop does not mask
        # the others; any failed read surfaces as 503 on the endpoint.
        tables = (
            "encrypted_batches",
            "encrypted_records",
            "encrypted_record_events",
            IDEMPOTENCY_TABLE,
        )
        for table in tables:
            with self.subTest(table=table):
                directory = Path(tempfile.mkdtemp())
                self.addCleanup(lambda d=directory: shutil.rmtree(d, True))
                # Seed and then drop on the *live* server: restarting would run
                # CREATE TABLE IF NOT EXISTS and recreate the dropped schema.
                harness = ServerHarness(make_config(directory))
                self.addCleanup(harness.close)
                body = json.dumps({"records": [sealed_record("a1")]}).encode("utf-8")
                request = urllib.request.Request(
                    harness.base + INGEST_PATH,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Tenant-ID": "acme",
                        "Idempotency-Key": "k-1",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request) as response:
                    self.assertEqual(response.status, 201)
                raw = connect(directory / "ledger.sqlite3")
                with raw:
                    raw.execute(f"DROP TABLE {table}")
                raw.close()
                request = urllib.request.Request(
                    harness.base + INTEGRITY_PATH,
                    headers={"X-Tenant-ID": "acme"},
                )
                try:
                    with urllib.request.urlopen(request) as response:
                        self.fail("expected 503")
                except urllib.error.HTTPError as exc:
                    with exc:
                        self.assertEqual(exc.code, 503)
                        self.assertEqual(json.loads(exc.read()), {"error": "storage_error"})

    def test_storage_failure_takes_precedence_over_corruption(self):
        # Corrupt data AND break a table the inspection must read: the failed
        # read wins with 503 rather than a 422 built on partial storage.
        _, created = self.ingest([sealed_record("a1"), sealed_record("a2")])
        self.tamper(
            "UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
            (created["batch_id"],),
        )
        self.tamper("DROP TABLE encrypted_record_events")
        self.assertEqual(self.integrity(), (503, {"error": "storage_error"}))

    def test_error_body_contains_only_error_field(self):
        _, created = self.ingest([sealed_record("a1")], key="k-1")
        self.tamper(
            "UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
            (created["batch_id"],),
        )
        _, body = self.integrity()
        self.assertEqual(body, {"error": "integrity_error"})

    # -- tenant isolation ---------------------------------------------------

    def test_other_tenants_corruption_does_not_affect_result(self):
        _, wanted = self.ingest([sealed_record("a1")], key="k-1", tenant="acme")
        _, other = self.ingest([sealed_record("b1")], key="k-2", tenant="beta")
        # Damage beta thoroughly; acme's review must not even load those rows.
        self.tamper(
            "UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
            (other["batch_id"],),
        )
        status, report = self.integrity(tenant="acme")
        self.assertEqual(status, 200)
        self.assertEqual(report["batch_count"], 1)
        self.assertEqual(report["record_count"], 1)
        self.assertEqual(report["binding_count"], 1)
        self.assertTrue(wanted["batch_id"])
        # Beta itself fails its own review.
        self.assertEqual(self.integrity(tenant="beta"), (422, {"error": "integrity_error"}))

    # -- read-only, replay, rollback ---------------------------------------

    def test_inspection_does_not_modify_storage(self):
        self.ingest([sealed_record("a1"), sealed_record("a2")], key="k-1")
        before = self._dump_tables()
        self.assertEqual(self.integrity()[0], 200)
        self.assertEqual(self.integrity()[0], 200)
        self.assertEqual(self._dump_tables(), before)

    def test_idempotent_replay_does_not_increase_totals(self):
        records = [sealed_record("a1"), sealed_record("a2")]
        self.ingest(copy.deepcopy(records), key="k-1")
        _, first = self.integrity()
        self.assertEqual(self.ingest(copy.deepcopy(records), key="k-1")[0], 200)
        _, second = self.integrity()
        self.assertEqual(second, first)
        self.assertEqual(second["batch_count"], 1)
        self.assertEqual(second["record_count"], 2)
        self.assertEqual(second["event_count"], 2)
        self.assertEqual(second["binding_count"], 1)

    def test_failed_commit_adds_nothing(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END"
            )
        raw.close()
        status, body = self.ingest([sealed_record("a1")], key="k-1")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        # The rolled-back batch, records, events and binding are all absent.
        self.assertEqual(
            self.integrity(),
            (
                200,
                {
                    "status": "ok",
                    "batch_count": 0,
                    "record_count": 0,
                    "event_count": 0,
                    "binding_count": 0,
                    "high_water": 0,
                },
            ),
        )

    # -- restart and rotation ----------------------------------------------

    def test_report_survives_restart(self):
        self.ingest([sealed_record("a1"), sealed_record("a2")], key="persist")
        self.ingest([sealed_record("b1")])
        _, before = self.integrity()
        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)
        self.assertEqual(self.integrity(), (200, before))

    def test_report_unaffected_by_key_rotation(self):
        self.ingest([sealed_record("a1")], key="k-1")
        _, before = self.integrity()
        request = urllib.request.Request(
            self.harness.base + "/v1/keys/rotate",
            data=json.dumps({"version": 2}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.integrity(), (200, before))

    # -- concurrency --------------------------------------------------------

    def test_concurrent_commits_observe_only_complete_serial_states(self):
        barrier = threading.Barrier(16)
        reports = []
        reports_lock = threading.Lock()

        def submit(index):
            barrier.wait()
            self.ingest([sealed_record(f"r{index}")])

        def inspect():
            barrier.wait()
            status, report = self.integrity()
            with reports_lock:
                reports.append((status, report))

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(8)]
        threads += [threading.Thread(target=inspect) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Acme is the only committer, so at every serial instant its seqs are
        # contiguous and the four numbers agree with the water; a reader never
        # sees a partial batch with unequal record/event counts.
        for status, report in reports:
            self.assertEqual(status, 200)
            self.assertEqual(report["record_count"], report["event_count"])
            self.assertEqual(report["record_count"], report["high_water"])
            self.assertLessEqual(report["batch_count"], 8)
        _, settled = self.integrity()
        self.assertEqual(settled["batch_count"], 8)
        self.assertEqual(settled["record_count"], 8)
        self.assertEqual(settled["event_count"], 8)
        self.assertEqual(settled["binding_count"], 0)
        self.assertEqual(settled["high_water"], 8)

    # -- helpers ------------------------------------------------------------

    def _dump_tables(self):
        raw = self.db()
        try:
            dump = {}
            for table in (
                "encrypted_batches",
                "encrypted_records",
                "encrypted_record_events",
                IDEMPOTENCY_TABLE,
            ):
                dump[table] = [
                    tuple(row) for row in raw.execute(f"SELECT * FROM {table}")
                ]
            return dump
        finally:
            raw.close()


if __name__ == "__main__":
    unittest.main()
