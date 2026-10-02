"""Contract tests for GET /v1/encrypted-records/batches/{batch_id}.

The endpoint reads back client-sealed batches committed by the sealed-write
ingress. Success shape, error precedence, cross-table integrity re-validation
and serial visibility under concurrency are all exercised here; most tampering
is performed directly on the SQLite file.
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


class EncryptedBatchReadTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant="acme"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = None
        if body is not None:
            if isinstance(body, (bytes, str)):
                data = body if isinstance(body, bytes) else body.encode("utf-8")
            else:
                data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.harness.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def ingest(self, records, tenant="acme"):
        return self.request("POST", INGEST_PATH, {"records": records}, tenant=tenant)

    def get_batch(self, batch_id, tenant="acme", query=""):
        suffix = f"?{query}" if query else ""
        return self.request(
            "GET", f"/v1/encrypted-records/batches/{batch_id}{suffix}", None, tenant=tenant
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

    # -- success -----------------------------------------------------------

    def test_success_returns_full_batch_in_submission_shape_and_order(self):
        records = [sealed_record("zeta"), sealed_record("alpha"), sealed_record("mid")]
        status, body = self.ingest(records)
        self.assertEqual(status, 201)
        batch_id = body["batch_id"]

        raw = self.db()
        try:
            created_at = raw.execute(
                "SELECT created_at FROM encrypted_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()[0]
        finally:
            raw.close()

        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["batch_id"], batch_id)
        self.assertEqual(body["count"], 3)
        self.assertEqual(body["created_at"], created_at)
        self.assertEqual([r["id"] for r in body["records"]], ["zeta", "alpha", "mid"])

        for source, returned in zip(records, body["records"]):
            self.assertEqual(
                returned,
                {
                    "id": source["id"],
                    "algorithm": source["algorithm"],
                    "key_id": source["key_id"],
                    "envelope": source["envelope"],
                    "ciphertext": source["ciphertext"],
                    "metadata": source["metadata"],
                },
            )

    def test_bytes_use_standard_padded_base64_round_trip(self):
        record = sealed_record("doc")
        batch_id = self.ingest([record])[1]["batch_id"]
        _, body = self.get_batch(batch_id)
        item = body["records"][0]
        # Standard alphabet only (no urlsafe chars) and padding preserved.
        for field in ("nonce", "wrapped_key"):
            value = item["envelope"][field]
            self.assertEqual(value, b64(base64.b64decode(value)))
            self.assertNotIn("-", value)
            self.assertNotIn("_", value)
        for field in ("data", "nonce", "tag"):
            value = item["ciphertext"][field]
            self.assertEqual(value, b64(base64.b64decode(value)))
        # 16-byte tags always carry standard "==" padding.
        self.assertTrue(item["ciphertext"]["tag"].endswith("=="))

    def test_empty_ciphertext_returns_empty_string(self):
        record = sealed_record("empty")
        record["ciphertext"]["data"] = ""
        batch_id = self.ingest([record])[1]["batch_id"]
        _, body = self.get_batch(batch_id)
        self.assertEqual(body["records"][0]["ciphertext"]["data"], "")

    def test_missing_key_id_and_metadata_return_null(self):
        record = sealed_record("doc")
        del record["key_id"]
        del record["metadata"]
        batch_id = self.ingest([record])[1]["batch_id"]
        _, body = self.get_batch(batch_id)
        item = body["records"][0]
        self.assertIsNone(item["key_id"])
        self.assertIsNone(item["metadata"])

    def test_metadata_recovers_as_object_with_values_unchanged(self):
        metadata = {
            "order": "A-100",
            "nested": {"b": [1, 2, {"c": "中文"}]},
            "n": None,
            "t": True,
            "f": 3.5,
        }
        record = sealed_record("doc", metadata=metadata)
        batch_id = self.ingest([record])[1]["batch_id"]
        _, body = self.get_batch(batch_id)
        self.assertEqual(body["records"][0]["metadata"], metadata)

    def test_aes128_batch_reads_back(self):
        record = sealed_record("doc", algorithm="AES-128-GCM")
        batch_id = self.ingest([record])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        item = body["records"][0]
        self.assertEqual(item["algorithm"], "AES-128-GCM")
        self.assertEqual(item["envelope"]["wrapped_key"], record["envelope"]["wrapped_key"])

    def test_batch_of_100_records_reads_in_order(self):
        records = [sealed_record(f"id_{i:03d}") for i in range(100)]
        batch_id = self.ingest(records)[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 100)
        self.assertEqual([r["id"] for r in body["records"]], [r["id"] for r in records])

    def test_distinct_batches_are_independently_readable(self):
        first = self.ingest([sealed_record("a")])[1]["batch_id"]
        second = self.ingest([sealed_record("b")])[1]["batch_id"]
        _, body_a = self.get_batch(first)
        _, body_b = self.get_batch(second)
        self.assertEqual([r["id"] for r in body_a["records"]], ["a"])
        self.assertEqual([r["id"] for r in body_b["records"]], ["b"])

    def test_query_parameters_are_ignored(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        for query in ("foo=bar", "limit=999", "x=1&y=2&batch_id=spoof", "="):
            with self.subTest(query=query):
                self.assertEqual(self.get_batch(batch_id, query=query)[0], 200)

    def test_batch_survives_restart_without_rewrite(self):
        records = [sealed_record("r0"), sealed_record("r1")]
        batch_id = self.ingest(records)[1]["batch_id"]
        before = self.get_batch(batch_id)[1]

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(after, before)

    # -- request validation and error precedence ---------------------------

    def test_missing_or_invalid_tenant_is_forbidden_before_batch_format(self):
        well_formed = "batch_" + "a" * 32
        for tenant, batch in (
            (None, well_formed),
            ("bad tenant!", well_formed),
            ("a/b", well_formed),
            (None, "not-a-batch"),
            ("bad tenant!", "nope"),
        ):
            with self.subTest(tenant=tenant, batch=batch):
                status, body = self.get_batch(batch, tenant=tenant)
                self.assertEqual((status, body), (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_malformed_batch_id_is_invalid_request(self):
        cases = [
            "",
            "batch_",
            "batch_" + "a" * 31,
            "batch_" + "a" * 33,
            "batch_" + "A" * 32,            # uppercase hex not allowed
            "batch_" + "g" * 32,            # non-hex
            "x" + "a" * 32,
            "batch_" + "a" * 32 + "/extra",
        ]
        for batch in cases:
            with self.subTest(batch=batch):
                status, body = self.get_batch(batch)
                self.assertEqual((status, body), (400, {"error": "invalid_request"}))

    def test_unknown_batch_is_not_found_with_bare_error_body(self):
        status, body = self.get_batch("batch_" + "f" * 32)
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_foreign_tenant_batch_is_not_found(self):
        batch_id = self.ingest([sealed_record("a")], tenant="alpha")[1]["batch_id"]
        self.assertEqual(self.get_batch(batch_id, tenant="beta"),
                         (404, {"error": "not_found"}))

    def test_foreign_tenant_gets_404_even_when_batch_details_are_corrupt(self):
        records = [sealed_record("a"), sealed_record("b")]
        batch_id = self.ingest(records, tenant="alpha")[1]["batch_id"]
        # Owner now sees an integrity problem; a foreign tenant must still get
        # 404 because ownership is decided without inspecting the batch.
        self.tamper("DELETE FROM encrypted_records WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.get_batch(batch_id, tenant="beta"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.get_batch(batch_id, tenant="alpha"),
                         (422, {"error": "integrity_error"}))

    def test_collection_path_serves_the_listing_endpoint(self):
        status, body = self.request("GET", "/v1/encrypted-records/batches")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": []})

    # -- integrity: batch/records/events drift -----------------------------

    def test_record_count_out_of_range_or_mismatched_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        for count in (0, 3, 101):
            self.tamper("UPDATE encrypted_batches SET record_count=? WHERE batch_id=?",
                        (count, batch_id))
            with self.subTest(count=count):
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))
        # A non-integer stored into the INTEGER-affinity column survives as text.
        self.tamper("UPDATE encrypted_batches SET record_count='two' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))
        self.tamper("UPDATE encrypted_batches SET record_count=2 WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id)[0], 200)

    def test_missing_extra_and_duplicate_record_positions_are_integrity_error(self):
        batch_id = self.ingest(
            [sealed_record("a"), sealed_record("b"), sealed_record("c")]
        )[1]["batch_id"]

        # Missing position 1: rows sit at positions 0 and 2.
        self.tamper("DELETE FROM encrypted_records WHERE batch_id=? AND id='b'", (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

        # Collapse the remaining row onto position 0: duplicate position.
        self.tamper("UPDATE encrypted_records SET position=0 WHERE batch_id=? AND id='c'",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

    def test_record_cross_tenant_or_cross_batch_link_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]

        self.tamper("UPDATE encrypted_records SET tenant='intruder' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

        self.tamper("UPDATE encrypted_records SET tenant='acme', batch_id='batch_%s' "
                    "WHERE id='a'" % ("0" * 32))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

    def test_event_missing_extra_misplaced_mismatched_and_cross_tenant(self):
        # Missing event.
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        self.tamper("DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

        # Extra event (duplicate position, the original position 0 still present).
        self.tamper("INSERT INTO encrypted_record_events (seq, batch_id, tenant, record_id, position) "
                    "VALUES (9001, ?, 'acme', 'a', 0)", (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))
        self.tamper("DELETE FROM encrypted_record_events WHERE seq=9001")

        # Misplaced event: positions 0 and 0 instead of 0 and 1.
        self.tamper("UPDATE encrypted_record_events SET position=0 "
                    "WHERE batch_id=? AND record_id='b'", (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

        # Event record id does not correspond to the record at that position.
        self.tamper("UPDATE encrypted_record_events SET position=1, record_id='ghost' "
                    "WHERE batch_id=? AND record_id='b'", (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

        # Event bound to another tenant.
        self.tamper("UPDATE encrypted_record_events SET record_id='b', tenant='intruder' "
                    "WHERE batch_id=? AND record_id='ghost'", (batch_id,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

    def test_extra_records_and_events_under_other_batch_do_not_leak_in(self):
        # A second, valid batch shares the table; the first batch must still
        # report exactly its own rows even though total table counts exceed it.
        first = self.ingest([sealed_record("a")])[1]["batch_id"]
        self.ingest([sealed_record("b")])
        status, body = self.get_batch(first)
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in body["records"]], ["a"])

    # -- integrity: stored field shapes ------------------------------------

    def test_corrupt_metadata_json_type_and_length_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        for value in ("not json", "5", '"a string"', "[1,2]", 42, "x" * 16385):
            self.tamper("UPDATE encrypted_records SET metadata=? WHERE id='a'", (value,))
            with self.subTest(value=value if not isinstance(value, str) else value[:12]):
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))

    def test_unsupported_or_typed_algorithm_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        # NOT NULL prevents storing NULL directly; tamper via raw SQL typing.
        for value in ("AES-256-CBC", "aes-256-gcm", 7):
            self.tamper("UPDATE encrypted_records SET algorithm=? WHERE id='a'", (value,))
            with self.subTest(value=value):
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))
        # Text affinity coerces a bound integer to '7'; verify it stays rejected.
        self.tamper("UPDATE encrypted_records SET algorithm='AES-256-GCM' WHERE id='a'")
        self.assertEqual(self.get_batch(batch_id)[0], 200)

    def test_bad_key_id_storage_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        # Overlong string stays text; an integer bound to the TEXT-affinity
        # column is coerced to '42', which remains a *valid* key id length --
        # type confusion in this column cannot be simulated through binding.
        self.tamper("UPDATE encrypted_records SET encryption_key_id=? WHERE id='a'",
                    ("k" * 129,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))
        self.tamper("UPDATE encrypted_records SET encryption_key_id=NULL WHERE id='a'")
        self.assertEqual(self.get_batch(batch_id)[0], 200)

    def test_wrong_length_or_type_blob_fields_are_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        cases = [
            ("envelope_nonce", b"short"),
            ("wrapped_key", b"x" * 12),
            ("ciphertext_nonce", b"x" * 11),
            ("tag", b"x" * 15),
            ("envelope_nonce", "not-a-blob"),
            ("ciphertext", "not-a-blob"),
        ]
        for column, value in cases:
            self.tamper(f"UPDATE encrypted_records SET {column}=? WHERE id='a'", (value,))
            with self.subTest(column=column, value=value):
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))

    def test_oversized_ciphertext_blob_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        self.tamper("UPDATE encrypted_records SET ciphertext=? WHERE id='a'",
                    (b"x" * 1048577,))
        self.assertEqual(self.get_batch(batch_id), (422, {"error": "integrity_error"}))

    def test_equal_length_ciphertext_change_is_returned_verbatim(self):
        record = sealed_record("a")
        batch_id = self.ingest([record])[1]["batch_id"]
        original = base64.b64decode(record["ciphertext"]["data"])
        flipped = bytearray(original)
        flipped[0] ^= 0xFF
        self.tamper("UPDATE encrypted_records SET ciphertext=? WHERE id='a'",
                    (bytes(flipped),))
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["records"][0]["ciphertext"]["data"], b64(bytes(flipped)))
        # No crypto verdict, no rejection of equal-length byte changes.
        self.assertNotEqual(body["records"][0]["ciphertext"]["data"],
                            record["ciphertext"]["data"])

    def test_read_does_not_modify_storage(self):
        record = sealed_record("a")
        batch_id = self.ingest([record])[1]["batch_id"]
        raw = self.db()
        try:
            before = raw.execute(
                "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                "FROM encrypted_records WHERE id='a'"
            ).fetchone()
            before = tuple(before)
            counts_before = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
            )
        finally:
            raw.close()
        for _ in range(3):
            self.assertEqual(self.get_batch(batch_id)[0], 200)
        raw = self.db()
        try:
            after = tuple(raw.execute(
                "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                "FROM encrypted_records WHERE id='a'"
            ).fetchone())
            counts_after = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
            )
        finally:
            raw.close()
        self.assertEqual(after, before)
        self.assertEqual(counts_after, counts_before)

    # -- storage failure ---------------------------------------------------

    def test_storage_failure_is_503_and_service_recovers(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.get_batch(batch_id), (503, {"error": "storage_error"}))
        # A 503 during the batch lookup happens even for unknown batch ids.
        self.assertEqual(self.get_batch("batch_" + "1" * 32),
                         (503, {"error": "storage_error"}))

        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TABLE encrypted_batches ("
                "batch_id TEXT NOT NULL PRIMARY KEY, tenant TEXT NOT NULL, "
                "record_count INTEGER NOT NULL, created_at TEXT NOT NULL)"
            )
        raw.close()
        new_status, new_body = self.ingest([sealed_record("later")])
        self.assertEqual(new_status, 201)
        self.assertEqual(self.get_batch(new_body["batch_id"])[0], 200)

    def test_storage_failure_on_records_query_is_503(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_records")
        raw.close()
        self.assertEqual(self.get_batch(batch_id), (503, {"error": "storage_error"}))

    # -- concurrency -------------------------------------------------------

    def test_concurrent_reads_see_only_committed_batches(self):
        seeded = [sealed_record(f"s{i}") for i in range(3)]
        stable_batch = self.ingest(seeded)[1]["batch_id"]
        expected_ids = [r["id"] for r in seeded]

        barrier = threading.Barrier(7)
        failures = []
        lock = threading.Lock()

        def reader():
            barrier.wait()
            for _ in range(60):
                status, body = self.get_batch(stable_batch)
                if status != 200:
                    with lock:
                        failures.append(("stable", status, body))
                    continue
                ids = [r["id"] for r in body["records"]]
                if ids != expected_ids or body["count"] != 3:
                    with lock:
                        failures.append(("shape", body))
                # Unknown batches never appear partially.
                probe = "batch_" + os.urandom(16).hex()
                status, body = self.get_batch(probe)
                if (status, body) != (404, {"error": "not_found"}):
                    with lock:
                        failures.append(("probe", status, body))

        def writer(index):
            barrier.wait()
            for _ in range(5):
                result = self.ingest(
                    [sealed_record(f"w{index}_{os.urandom(4).hex()}{i}") for i in range(3)]
                )
                if result[0] != 201:
                    with lock:
                        failures.append(("write", result))
                else:
                    # The just-committed batch must be immediately complete.
                    status, body = self.get_batch(result[1]["batch_id"])
                    if status != 200 or body["count"] != 3:
                        with lock:
                            failures.append(("readown", status, body))

        threads = [threading.Thread(target=reader) for _ in range(4)]
        threads += [threading.Thread(target=writer, args=(i,)) for i in range(2)]

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
            if status != 200:
                with lock:
                    failures.append(("rotate", status, body))

        threads.append(threading.Thread(target=rotate))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        # Sealed records do not participate in rotation; still fully readable.
        status, body = self.get_batch(stable_batch)
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in body["records"]], expected_ids)

    # -- existing endpoints unchanged --------------------------------------

    def test_plaintext_endpoints_still_work_alongside(self):
        status, body = self.request("POST", "/v1/records",
                                    {"id": "p1", "plaintext": "原文"})
        self.assertEqual((status, body), (201, {"id": "p1", "key_version": 1}))
        self.assertEqual(self.request("GET", "/v1/records/p1"),
                         (200, {"id": "p1", "plaintext": "原文", "key_version": 1}))
        self.assertEqual(self.request("GET", "/health", None, None)[0], 200)


if __name__ == "__main__":
    unittest.main()
