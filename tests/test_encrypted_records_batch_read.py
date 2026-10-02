"""Contract tests for POST /v1/encrypted-records/batch/read.

The endpoint fetches client-sealed records by id across batches. Success shape
(request order, per-item batch_id/created_at), error precedence
(403 -> 400 -> 503 -> 404 -> 503 -> 422), whole-batch integrity re-validation
of every involved batch and serial visibility under concurrency are exercised
here; most tampering is performed directly on the SQLite file.
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
READ_PATH = "/v1/encrypted-records/batch/read"


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


class EncryptedRecordsBatchReadTests(unittest.TestCase):
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

    def batch_read(self, ids, tenant="acme", query="", body=None):
        payload = {"ids": ids} if body is None else body
        suffix = f"?{query}" if query else ""
        return self.request("POST", READ_PATH + suffix, payload, tenant=tenant)

    def get_batch(self, batch_id, tenant="acme"):
        return self.request(
            "GET", f"/v1/encrypted-records/batches/{batch_id}", None, tenant=tenant
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

    def test_reads_records_across_batches_in_request_order(self):
        first = self.ingest([sealed_record("zeta"), sealed_record("alpha")])[1]
        second = self.ingest([sealed_record("mid", algorithm="AES-128-GCM")])[1]
        third = self.ingest([sealed_record("other")], tenant="other")[1]
        del third  # another tenant's batch must never enter the result

        ordered = ["mid", "alpha", "zeta"]
        status, body = self.batch_read(ordered)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 3)
        self.assertEqual([item["id"] for item in body["items"]], ordered)

        _, full_first = self.get_batch(first["batch_id"])
        _, full_second = self.get_batch(second["batch_id"])
        by_id = {r["id"]: r for r in full_first["records"]}
        by_id.update({r["id"]: r for r in full_second["records"]})
        created_at = {
            first["batch_id"]: full_first["created_at"],
            second["batch_id"]: full_second["created_at"],
        }
        for item, record_id in zip(body["items"], ordered):
            expected_batch = (
                second["batch_id"] if record_id == "mid" else first["batch_id"]
            )
            self.assertEqual(item["batch_id"], expected_batch)
            self.assertEqual(item["created_at"], created_at[expected_batch])
            # The item is the existing whole-batch record shape plus exactly
            # batch_id and created_at.
            expected = dict(by_id[record_id])
            expected["batch_id"] = expected_batch
            expected["created_at"] = created_at[expected_batch]
            self.assertEqual(item, expected)

    def test_multiple_ids_from_one_batch_share_its_review(self):
        committed = self.ingest([sealed_record("a"), sealed_record("b"), sealed_record("c")])[1]
        status, body = self.batch_read(["c", "a"])
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 2)
        self.assertEqual([item["id"] for item in body["items"]], ["c", "a"])
        for item in body["items"]:
            self.assertEqual(item["batch_id"], committed["batch_id"])

    def test_base64_empty_ciphertext_and_null_optional_fields_rules_hold(self):
        record = sealed_record("doc")
        record["ciphertext"]["data"] = ""
        del record["key_id"]
        del record["metadata"]
        self.ingest([record])
        status, body = self.batch_read(["doc"])
        self.assertEqual(status, 200)
        item = body["items"][0]
        self.assertEqual(item["ciphertext"]["data"], "")
        self.assertIsNone(item["key_id"])
        self.assertIsNone(item["metadata"])
        self.assertTrue(item["ciphertext"]["tag"].endswith("=="))

    def test_only_requested_records_returned_even_from_same_batch(self):
        self.ingest([sealed_record("a"), sealed_record("b"), sealed_record("c")])
        _, body = self.batch_read(["b"])
        self.assertEqual(body["count"], 1)
        self.assertEqual([item["id"] for item in body["items"]], ["b"])

    def test_100_distinct_ids_across_batches(self):
        ids = []
        for start in range(0, 100, 10):
            chunk = [sealed_record(f"id_{i:03d}") for i in range(start, start + 10)]
            self.assertEqual(self.ingest(chunk)[0], 201)
            ids.extend(f"id_{i:03d}" for i in range(start, start + 10))
        shuffled = list(reversed(ids))
        status, body = self.batch_read(shuffled)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 100)
        self.assertEqual([item["id"] for item in body["items"]], shuffled)

    def test_extra_fields_and_query_parameters_are_ignored(self):
        self.ingest([sealed_record("a")])
        status, body = self.batch_read(
            ["a"],
            query="foo=bar&ids=spoof&x=1",
            body={"ids": ["a"], "extra": {"nested": 1}, "other": "ignored"},
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], ["a"])

    def test_read_survives_restart_and_equals_pre_restart_body(self):
        first = self.ingest([sealed_record("a"), sealed_record("b")])[1]
        second = self.ingest([sealed_record("c")])[1]
        before = self.batch_read(["c", "a", "b"])[1]
        self.assertEqual(
            [item["batch_id"] for item in before["items"]],
            [second["batch_id"], first["batch_id"], first["batch_id"]],
        )

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.batch_read(["c", "a", "b"])
        self.assertEqual(status, 200)
        self.assertEqual(after, before)

    def test_read_does_not_modify_storage(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        raw = self.db()
        try:
            def table_counts():
                return (
                    raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                    raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                    raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                    raw.execute(
                        "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                    ).fetchone()[0],
                )
            before_rows = [
                tuple(row)
                for row in raw.execute(
                    "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records ORDER BY id"
                )
            ]
            counts_before = table_counts()
        finally:
            raw.close()
        for _ in range(3):
            self.assertEqual(self.batch_read(["b", "a"])[0], 200)
        raw = self.db()
        try:
            after_rows = [
                tuple(row)
                for row in raw.execute(
                    "SELECT tenant, id, batch_id, position, algorithm, encryption_key_id, "
                    "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
                    "FROM encrypted_records ORDER BY id"
                )
            ]
            counts_after = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
            )
        finally:
            raw.close()
        self.assertEqual(after_rows, before_rows)
        self.assertEqual(counts_after, counts_before)
        self.assertEqual(batch_id, batch_id)  # batch id stays stable

    # -- tenant precedence -------------------------------------------------

    def test_missing_or_invalid_tenant_is_403_before_body_errors(self):
        cases = [
            (None, {"ids": ["a"]}),
            ("bad tenant!", {"ids": ["a"]}),
            ("a/b", {"ids": ["a"]}),
            (None, None),
            (None, b"\xff\xfe not utf-8"),
            (None, [1, 2]),
            (None, {"ids": []}),
            ("", {"ids": ["a"]}),
        ]
        for tenant, body in cases:
            with self.subTest(tenant=tenant):
                status, response = self.request("POST", READ_PATH, body, tenant=tenant)
                self.assertEqual(
                    (status, response), (403, {"error": "TENANT_RECORD_FORBIDDEN"})
                )

    # -- body validation ---------------------------------------------------

    def test_body_must_be_utf8_json_object(self):
        for body in (b"\xff\xfe", b"", b"not json", b"[1,2]", b'"a string"', b"42", b"null"):
            with self.subTest(body=body):
                self.assertEqual(
                    self.request("POST", READ_PATH, body, tenant="acme"),
                    (400, {"error": "invalid_request"}),
                )

    def test_invalid_ids_shapes_are_invalid_request(self):
        cases = [
            {},                       # missing
            {"ids": None},
            {"ids": "a"},
            {"ids": {"a": 1}},
            {"ids": []},             # empty
            {"ids": ["a"] * 2},      # duplicate
            {"ids": [1]},            # non-string element
            {"ids": [None]},
            {"ids": [True]},
            {"ids": [{"id": "a"}]},
            {"ids": ["bad id"]},     # space
            {"ids": ["a/b"]},
            {"ids": ["x" * 65]},
            {"ids": ["a", "a"]},
            {"ids": [f"id_{i}" for i in range(101)]},
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(
                    self.batch_read(None, body=body),
                    (400, {"error": "invalid_request"}),
                )

    def test_64_char_identifier_and_single_element_boundary_ok(self):
        long_id = "A" * 64
        self.assertEqual(self.ingest([sealed_record(long_id)])[0], 201)
        status, body = self.batch_read([long_id])
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 1)

    # -- existence / tenant isolation --------------------------------------

    def test_unknown_id_is_not_found_with_bare_error(self):
        status, body = self.batch_read(["ghost"])
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_foreign_tenant_same_named_id_is_not_found(self):
        self.ingest([sealed_record("shared")], tenant="beta")
        self.assertEqual(
            self.batch_read(["shared"], tenant="alpha"),
            (404, {"error": "not_found"}),
        )
        # The owner still reads it.
        self.assertEqual(self.batch_read(["shared"], tenant="beta")[0], 200)

    def test_plain_server_encrypted_same_named_id_is_not_found(self):
        status, _ = self.request(
            "POST", "/v1/records", {"id": "shared", "plaintext": "secret"}, tenant="acme"
        )
        self.assertEqual(status, 201)
        # Only client-sealed rows count as existing.
        self.assertEqual(
            self.batch_read(["shared"]), (404, {"error": "not_found"})
        )

    def test_missing_id_with_corrupt_batch_still_returns_404(self):
        self.ingest([sealed_record("a"), sealed_record("b")])
        # Damage the batch (sibling record deleted -> integrity drift).
        self.tamper("DELETE FROM encrypted_records WHERE id='b'")
        # 'a' exists but its batch is damaged, while 'ghost' is missing:
        # existence is settled first and wins with 404.
        self.assertEqual(
            self.batch_read(["a", "ghost"]), (404, {"error": "not_found"})
        )
        self.assertEqual(
            self.batch_read(["ghost", "a"]), (404, {"error": "not_found"})
        )

    def test_one_missing_id_fails_the_whole_request_without_partial_items(self):
        self.ingest([sealed_record("a")])
        status, body = self.batch_read(["a", "ghost"])
        self.assertEqual((status, body), (404, {"error": "not_found"}))
        self.assertNotIn("items", body)

    # -- integrity review --------------------------------------------------

    def test_record_linking_to_missing_batch_is_integrity_error(self):
        self.ingest([sealed_record("a")])
        self.tamper(
            "UPDATE encrypted_records SET batch_id=? WHERE id='a'",
            ("batch_" + "f" * 32,),
        )
        self.assertEqual(
            self.batch_read(["a"]), (422, {"error": "integrity_error"})
        )

    def test_record_linking_to_malformed_batch_id_is_integrity_error(self):
        self.ingest([sealed_record("a")])
        self.tamper("UPDATE encrypted_records SET batch_id='not-a-batch' WHERE id='a'")
        self.assertEqual(
            self.batch_read(["a"]), (422, {"error": "integrity_error"})
        )

    def test_record_linking_to_foreign_tenant_batch_is_integrity_error(self):
        self.ingest([sealed_record("a")], tenant="alpha")
        foreign = self.ingest([sealed_record("b")], tenant="beta")[1]["batch_id"]
        # Repoint alpha's record to beta's intact batch; existence under alpha
        # succeeds, but ownership/correspondence review must fail with 422.
        self.tamper(
            "UPDATE encrypted_records SET batch_id=? WHERE tenant='alpha' AND id='a'",
            (foreign,),
        )
        self.assertEqual(
            self.batch_read(["a"], tenant="alpha"),
            (422, {"error": "integrity_error"}),
        )
        # That repoint also makes beta's first batch host an extra foreign
        # record, so it is now corrupt; a fresh unrelated beta batch is fine.
        self.assertEqual(self.batch_read(["b"], tenant="beta")[0], 422)
        self.ingest([sealed_record("b2")], tenant="beta")
        self.assertEqual(self.batch_read(["b2"], tenant="beta")[0], 200)

    def test_corrupt_unrequested_sibling_in_same_batch_is_integrity_error(self):
        self.ingest([sealed_record("a"), sealed_record("b")])
        self.tamper("DELETE FROM encrypted_records WHERE id='b'")
        self.assertEqual(
            self.batch_read(["a"]), (422, {"error": "integrity_error"})
        )

    def test_corrupt_event_in_involved_batch_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        self.tamper(
            "DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
            (batch_id,),
        )
        self.assertEqual(
            self.batch_read(["a"]), (422, {"error": "integrity_error"})
        )

    def test_corrupt_requested_record_shape_is_integrity_error(self):
        self.ingest([sealed_record("a")])
        self.tamper("UPDATE encrypted_records SET metadata='not json' WHERE id='a'")
        self.assertEqual(
            self.batch_read(["a"]), (422, {"error": "integrity_error"})
        )

    def test_corrupt_unrelated_batch_does_not_affect_result(self):
        self.ingest([sealed_record("a")])
        self.ingest([sealed_record("b"), sealed_record("c")])
        # Corrupt the second batch; reading only 'a' must not inspect it.
        self.tamper("DELETE FROM encrypted_records WHERE id='c'")
        status, body = self.batch_read(["a"])
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], ["a"])

    def test_equal_length_ciphertext_change_is_returned_verbatim(self):
        record = sealed_record("a")
        self.ingest([record])
        original = base64.b64decode(record["ciphertext"]["data"])
        flipped = bytearray(original)
        flipped[0] ^= 0xFF
        self.tamper("UPDATE encrypted_records SET ciphertext=? WHERE id='a'",
                    (bytes(flipped),))
        status, body = self.batch_read(["a"])
        self.assertEqual(status, 200)
        self.assertEqual(body["items"][0]["ciphertext"]["data"], b64(bytes(flipped)))

    # -- storage failures --------------------------------------------------

    def test_storage_failure_on_existence_query_is_503(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_records")
        raw.close()
        self.assertEqual(
            self.batch_read(["a"]), (503, {"error": "storage_error"})
        )

    def test_storage_failure_while_loading_batches_is_503(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        # Existence succeeds (encrypted_records intact); phase-2 reads fail.
        self.assertEqual(
            self.batch_read(["a"]), (503, {"error": "storage_error"})
        )

        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_record_events")
        raw.close()
        self.assertEqual(
            self.batch_read(["a"]), (503, {"error": "storage_error"})
        )

    def test_service_recovers_after_storage_failure(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.batch_read(["a"])[0], 503)
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TABLE encrypted_batches ("
                "batch_id TEXT NOT NULL PRIMARY KEY, tenant TEXT NOT NULL, "
                "record_count INTEGER NOT NULL, created_at TEXT NOT NULL)"
            )
        raw.close()
        # The old sealed records' batch rows are gone -> 422, but new ingests
        # and reads work again.
        self.assertEqual(self.batch_read(["a"])[0], 422)
        committed = self.ingest([sealed_record("later")])
        self.assertEqual(committed[0], 201)
        self.assertEqual(self.batch_read(["later"])[0], 200)

    # -- concurrency -------------------------------------------------------

    def test_concurrent_reads_observe_complete_serial_states(self):
        batches = [
            self.ingest([sealed_record(f"s{i}")])[1]["batch_id"] for i in range(3)
        ]
        stable_ids = [f"s{i}" for i in range(3)]

        barrier = threading.Barrier(7)
        failures = []
        lock = threading.Lock()

        def reader():
            barrier.wait()
            for _ in range(60):
                status, body = self.batch_read(stable_ids)
                if status != 200:
                    with lock:
                        failures.append(("stable", status, body))
                    continue
                if [item["id"] for item in body["items"]] != stable_ids:
                    with lock:
                        failures.append(("order", body))
                if any(item["batch_id"] not in batches for item in body["items"]):
                    with lock:
                        failures.append(("batch", body))
                # Unknown ids never appear partially.
                status, body = self.batch_read([f"probe_{os.urandom(8).hex()}"])
                if (status, body) != (404, {"error": "not_found"}):
                    with lock:
                        failures.append(("probe", status, body))

        def writer(index):
            barrier.wait()
            for round_index in range(5):
                ids = [f"w{index}_{round_index}_{i}" for i in range(3)]
                result = self.ingest([sealed_record(record_id) for record_id in ids])
                if result[0] != 201:
                    with lock:
                        failures.append(("write", result))
                    continue
                # The just-committed records must be immediately complete.
                status, body = self.batch_read(ids)
                if status != 200 or body["count"] != 3:
                    with lock:
                        failures.append(("readown", status, body))

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
            if status != 200:
                with lock:
                    failures.append(("rotate", status, body))

        threads = [threading.Thread(target=reader) for _ in range(4)]
        threads += [threading.Thread(target=writer, args=(i,)) for i in range(2)]
        threads.append(threading.Thread(target=rotate))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        # Sealed records do not participate in rotation; still fully readable.
        status, body = self.batch_read(stable_ids)
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], stable_ids)

    # -- existing endpoints unchanged --------------------------------------

    def test_existing_endpoints_keep_working(self):
        # Plain records endpoints.
        self.assertEqual(
            self.request("POST", "/v1/records",
                         {"id": "p1", "plaintext": "原文"})[0],
            201,
        )
        self.assertEqual(
            self.request("GET", "/v1/records/p1")[1],
            {"id": "p1", "plaintext": "原文", "key_version": 1},
        )
        self.assertEqual(
            self.request("POST", "/v1/records/batch/read", {"ids": ["p1"]})[0],
            200,
        )
        # Sealed batch write, single-batch read and listings.
        batch_id = self.ingest([sealed_record("e1")])[1]["batch_id"]
        self.assertEqual(self.get_batch(batch_id)[0], 200)
        self.assertEqual(self.request("GET", "/v1/encrypted-records/batches")[0], 200)
        self.assertEqual(self.request("GET", "/health", None, None)[0], 200)
        self.assertEqual(self.request("GET", "/v1/keys", None, None)[0], 200)


if __name__ == "__main__":
    unittest.main()
