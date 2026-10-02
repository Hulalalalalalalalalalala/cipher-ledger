"""Contract tests for the optional Idempotency-Key header on the sealed batch
ingress (POST /v1/encrypted-records/batch).

The header lets a client whose response was lost retry and recover the
original batch: same tenant + same key + same content replays the first
success body with 200, same key + different content is 409, and the binding
commits atomically with the batch it names.
"""

import base64
import http.client
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
ENCRYPTED_PATH = "/v1/encrypted-records/batch"


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
    """A syntactically valid pre-sealed record; override any field for tests."""
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


class IdempotencyTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, body, tenant="acme", key=None, raw=None, extra_headers=None):
        headers = {"Content-Type": "application/json"}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        if key is not None:
            headers["Idempotency-Key"] = key
        if extra_headers:
            headers.update(extra_headers)
        data = raw if raw is not None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.harness.base + ENCRYPTED_PATH, data=data,
                                         headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def raw_request(self, data, header_pairs):
        """POST with an explicit ordered header list (allows duplicates)."""
        host, port = self.harness.base.removeprefix("http://").split(":")
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            connection.putrequest("POST", ENCRYPTED_PATH)
            for name, value in header_pairs:
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(data)))
            connection.endheaders(data)
            response = connection.getresponse()
            payload = response.read()
            return response.status, json.loads(payload) if payload else {}
        finally:
            connection.close()

    def ingest(self, records, tenant="acme", key=None):
        return self.request({"records": records}, tenant=tenant, key=key)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def bindings(self):
        raw = self.db()
        try:
            return [tuple(row) for row in raw.execute(
                "SELECT tenant, idem_key, batch_id FROM encrypted_idempotency_keys")]
        finally:
            raw.close()

    def store_counts(self):
        raw = self.db()
        try:
            return tuple(raw.execute(
                "SELECT (SELECT COUNT(*) FROM encrypted_batches), "
                "(SELECT COUNT(*) FROM encrypted_records), "
                "(SELECT COUNT(*) FROM encrypted_record_events), "
                "(SELECT COUNT(*) FROM encrypted_idempotency_keys)").fetchone())
        finally:
            raw.close()

    # -- header validation ---------------------------------------------------

    def test_invalid_keys_are_invalid_batch_naming_the_header(self):
        for bad in ("", "has space", "dot.key", "x" * 65, "bang!key"):
            with self.subTest(key=bad):
                status, body = self.ingest([sealed_record("a")], key=bad)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "INVALID_BATCH")
                self.assertIn("Idempotency-Key", body["message"])
        self.assertEqual(self.store_counts(), (0, 0, 0, 0))

    def test_duplicate_header_is_invalid_batch(self):
        data = json.dumps({"records": [sealed_record("a")]}).encode()
        status, body = self.raw_request(data, [
            ("X-Tenant-ID", "acme"),
            ("Content-Type", "application/json"),
            ("Idempotency-Key", "key-one"),
            ("Idempotency-Key", "key-two"),
        ])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        self.assertIn("Idempotency-Key", body["message"])
        self.assertEqual(self.store_counts(), (0, 0, 0, 0))

    def test_key_is_case_sensitive(self):
        self.assertEqual(self.ingest([sealed_record("a")], key="CaseKey")[0], 201)
        # Differently-cased key is a different key: fresh write, not a replay.
        status, body = self.ingest([sealed_record("b")], key="casekey")
        self.assertEqual(status, 201)
        self.assertEqual(sorted(k for _, k, _ in self.bindings()),
                         ["CaseKey", "casekey"])

    def test_header_validated_after_shape_and_duplicate_checks(self):
        # Malformed body wins over a malformed key (shape is checked first).
        status, body = self.request({"records": []}, key="bad key!")
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("records", body["message"])
        # In-batch duplicate wins over a malformed key.
        records = [sealed_record("dup"), sealed_record("dup")]
        status, body = self.ingest(records, key="bad key!")
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("records[1].id", body["message"])

    def test_tenant_rules_still_take_precedence(self):
        # Missing/invalid tenant identity is 403 even with a malformed key.
        status, body = self.ingest([sealed_record("a")], tenant="bad tenant!",
                                   key="bad key!")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))
        # A cross-tenant claim is 403 even with a malformed key.
        record = sealed_record("a")
        record["tenant"] = "other"
        status, body = self.ingest([record], key="bad key!")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))

    # -- first write and replay ----------------------------------------------

    def test_new_key_commits_and_binds(self):
        records = [sealed_record("alpha"), sealed_record("beta")]
        status, body = self.ingest(records, key="order-42")
        self.assertEqual(status, 201)
        self.assertEqual(body["count"], 2)
        self.assertEqual([r["id"] for r in body["results"]], ["alpha", "beta"])
        self.assertEqual(self.bindings(), [("acme", "order-42", body["batch_id"])])

    def test_same_key_same_content_replays_original_batch(self):
        records = [sealed_record("zeta"), sealed_record("alpha")]
        first_status, first = self.ingest(records, key="retry-1")
        self.assertEqual(first_status, 201)
        status, body = self.ingest(records, key="retry-1")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)
        # Nothing new was persisted: one batch, two records, two events, one key.
        self.assertEqual(self.store_counts(), (1, 2, 2, 1))

    def test_replay_body_is_byte_identical_to_first_success(self):
        records = [sealed_record(f"r{i}") for i in range(5)]
        _, first = self.ingest(records, key="k")
        for _ in range(3):
            status, body = self.ingest(records, key="k")
            self.assertEqual(status, 200)
            self.assertEqual(body, first)

    def test_replayed_batch_is_readable_by_batch_id(self):
        records = [sealed_record("a"), sealed_record("b")]
        _, first = self.ingest(records, key="k")
        _, replay = self.ingest(records, key="k")
        request = urllib.request.Request(
            self.harness.base + "/v1/encrypted-records/batches/" + replay["batch_id"],
            headers={"X-Tenant-ID": "acme"})
        with urllib.request.urlopen(request) as response:
            fetched = json.loads(response.read())
        self.assertEqual(fetched["batch_id"], first["batch_id"])
        self.assertEqual([r["id"] for r in fetched["records"]], ["a", "b"])

    def test_no_header_keeps_existing_write_behavior(self):
        self.assertEqual(self.ingest([sealed_record("a")])[0], 201)
        self.assertEqual(self.ingest([sealed_record("b")])[0], 201)
        # No bindings are created, and duplicate ids still conflict.
        self.assertEqual(self.bindings(), [])
        status, body = self.ingest([sealed_record("a")])
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))

    def test_key_is_scoped_per_tenant(self):
        records_a = [sealed_record("shared")]
        _, first = self.ingest(records_a, tenant="alpha", key="k")
        records_b = [sealed_record("other")]
        status, second = self.ingest(records_b, tenant="beta", key="k")
        self.assertEqual(status, 201)
        self.assertNotEqual(first["batch_id"], second["batch_id"])
        self.assertEqual(sorted(self.bindings()),
                         [("alpha", "k", first["batch_id"]),
                          ("beta", "k", second["batch_id"])])

    def test_binding_survives_restart(self):
        records = [sealed_record("a")]
        _, first = self.ingest(records, key="durable")
        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        status, body = self.ingest(records, key="durable")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    # -- content equivalence -------------------------------------------------

    def test_json_layout_and_key_order_do_not_affect_comparison(self):
        records = [sealed_record("a", metadata={"x": 1, "y": [1, 2]})]
        _, first = self.ingest(records, key="k")
        # Same content, reserialized: pretty-printed, reordered object keys.
        reordered = [{"metadata": {"y": [1, 2], "x": 1},
                      "ciphertext": records[0]["ciphertext"],
                      "envelope": records[0]["envelope"],
                      "key_id": records[0]["key_id"],
                      "algorithm": records[0]["algorithm"],
                      "id": "a"}]
        raw = json.dumps({"records": reordered}, indent=3).encode()
        status, body = self.request(None, key="k", raw=raw)
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    def test_ignored_fields_do_not_affect_comparison(self):
        records = [sealed_record("a")]
        _, first = self.ingest(records, key="k")
        replay = [dict(records[0], unknown_field="ignored", tenant="acme")]
        status, body = self.request({"records": replay, "also_ignored": True}, key="k")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    def test_omitted_and_null_key_id_and_metadata_are_equivalent(self):
        record = sealed_record("a")
        del record["key_id"]
        del record["metadata"]
        _, first = self.ingest([record], key="k")
        replay = [dict(record, key_id=None, metadata=None)]
        status, body = self.ingest(replay, key="k")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    def test_metadata_numbers_compare_by_value(self):
        records = [sealed_record("a", metadata={"n": 1, "list": [2, 3.0]})]
        _, first = self.ingest(records, key="k")
        replay = [dict(records[0], metadata={"n": 1.0, "list": [2.0, 3]})]
        status, body = self.ingest(replay, key="k")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    def test_metadata_boolean_differs_from_number(self):
        records = [sealed_record("a", metadata={"flag": 1})]
        self.assertEqual(self.ingest(records, key="k")[0], 201)
        replay = [dict(records[0], metadata={"flag": True})]
        status, body = self.ingest(replay, key="k")
        self.assertEqual((status, body), (409, {"error": "IDEMPOTENCY_CONFLICT"}))

    def test_record_order_and_array_order_matter(self):
        records = [sealed_record("a"), sealed_record("b")]
        self.assertEqual(self.ingest(records, key="k")[0], 201)
        status, _ = self.ingest(list(reversed(records)), key="k")
        self.assertEqual(status, 409)
        records = [sealed_record("c", metadata={"v": [1, 2]})]
        self.assertEqual(self.ingest(records, key="m")[0], 201)
        replay = [dict(records[0], metadata={"v": [2, 1]})]
        self.assertEqual(self.ingest(replay, key="m")[0], 409)

    def test_byte_fields_compare_decoded_values(self):
        records = [sealed_record("a")]
        self.assertEqual(self.ingest(records, key="k")[0], 201)
        # Same decoded bytes -> replay; any single decoded byte differs -> 409.
        changed = [sealed_record("a")]
        changed[0]["envelope"] = dict(records[0]["envelope"])
        changed[0]["ciphertext"] = records[0]["ciphertext"]
        changed[0]["key_id"] = records[0]["key_id"]
        changed[0]["metadata"] = records[0]["metadata"]
        raw = bytearray(base64.b64decode(changed[0]["envelope"]["nonce"]))
        raw[0] ^= 1
        changed[0]["envelope"]["nonce"] = b64(bytes(raw))
        status, body = self.ingest(changed, key="k")
        self.assertEqual((status, body), (409, {"error": "IDEMPOTENCY_CONFLICT"}))

    # -- conflicts -------------------------------------------------------------

    def test_same_key_different_content_is_conflict(self):
        self.assertEqual(self.ingest([sealed_record("a")], key="k")[0], 201)
        status, body = self.ingest([sealed_record("b")], key="k")
        self.assertEqual((status, body), (409, {"error": "IDEMPOTENCY_CONFLICT"}))
        # The conflict writes nothing and the binding still points at batch one.
        self.assertEqual(self.store_counts(), (1, 1, 1, 1))

    def test_conflict_wins_even_when_ids_already_exist(self):
        self.assertEqual(self.ingest([sealed_record("a")], key="k")[0], 201)
        # Different content under the same key whose id also exists: 409, not 400.
        status, body = self.ingest([sealed_record("a")], key="k")
        self.assertEqual((status, body), (409, {"error": "IDEMPOTENCY_CONFLICT"}))

    def test_new_key_with_existing_id_is_invalid_batch_and_not_bound(self):
        self.assertEqual(self.ingest([sealed_record("old")])[0], 201)
        status, body = self.ingest([sealed_record("old")], key="fresh-key")
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("records[0].id", body["message"])
        self.assertEqual(self.bindings(), [])
        # The key is still free: a non-conflicting body binds it normally.
        status, _ = self.ingest([sealed_record("new")], key="fresh-key")
        self.assertEqual(status, 201)
        self.assertEqual(len(self.bindings()), 1)

    # -- atomicity and failure -------------------------------------------------

    def test_failed_commit_does_not_bind_the_key(self):
        raw = self.db()
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON "
                        "encrypted_records BEGIN SELECT RAISE(ABORT, 'no'); END")
        raw.close()
        records = [sealed_record("a"), sealed_record("b")]
        status, body = self.ingest(records, key="k")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        self.assertEqual(self.store_counts(), (0, 0, 0, 0))
        # After recovery the same key retries cleanly and commits.
        raw = self.db()
        with raw:
            raw.execute("DROP TRIGGER block_encrypted_insert")
        raw.close()
        status, body = self.ingest(records, key="k")
        self.assertEqual(status, 201)
        self.assertEqual(self.bindings(), [("acme", "k", body["batch_id"])])

    def test_idempotency_lookup_failure_is_batch_write_failed(self):
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_idempotency_keys")
        raw.close()
        status, body = self.ingest([sealed_record("a")], key="k")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        raw = self.db()
        try:
            counts = raw.execute(
                "SELECT (SELECT COUNT(*) FROM encrypted_batches), "
                "(SELECT COUNT(*) FROM encrypted_records), "
                "(SELECT COUNT(*) FROM encrypted_record_events)").fetchone()
        finally:
            raw.close()
        self.assertEqual(tuple(counts), (0, 0, 0))

    def test_existing_records_and_bindings_survive_failed_batch(self):
        records = [sealed_record("keep")]
        _, first = self.ingest(records, key="good")
        self.assertEqual(self.store_counts(), (1, 1, 1, 1))
        raw = self.db()
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON "
                        "encrypted_records BEGIN SELECT RAISE(ABORT, 'no'); END")
        raw.close()
        self.assertEqual(self.ingest([sealed_record("nope")], key="bad")[0], 500)
        self.assertEqual(self.store_counts(), (1, 1, 1, 1))
        # The surviving binding still replays.
        status, body = self.ingest(records, key="good")
        self.assertEqual(status, 200)
        self.assertEqual(body, first)

    # -- replay integrity --------------------------------------------------------

    def test_replay_with_missing_batch_is_integrity_error(self):
        records = [sealed_record("a")]
        _, first = self.ingest(records, key="k")
        raw = self.db()
        with raw:
            raw.execute("DELETE FROM encrypted_batches WHERE batch_id=?",
                        (first["batch_id"],))
        raw.close()
        status, body = self.ingest(records, key="k")
        self.assertEqual((status, body), (422, {"error": "integrity_error"}))

    def test_replay_with_cross_tenant_batch_is_integrity_error(self):
        _, foreign = self.ingest([sealed_record("x")], tenant="beta", key="fk")
        records = [sealed_record("a")]
        _, mine = self.ingest(records, tenant="acme", key="k")
        raw = self.db()
        with raw:
            raw.execute("UPDATE encrypted_idempotency_keys SET batch_id=? "
                        "WHERE tenant='acme' AND idem_key='k'",
                        (foreign["batch_id"],))
        raw.close()
        status, body = self.ingest(records, tenant="acme", key="k")
        self.assertEqual((status, body), (422, {"error": "integrity_error"}))
        self.assertNotEqual(mine["batch_id"], foreign["batch_id"])

    def test_replay_with_broken_batch_consistency_is_integrity_error(self):
        records = [sealed_record("a"), sealed_record("b")]
        _, first = self.ingest(records, key="k")
        raw = self.db()
        with raw:
            raw.execute("DELETE FROM encrypted_record_events WHERE batch_id=? "
                        "AND position=1", (first["batch_id"],))
        raw.close()
        status, body = self.ingest(records, key="k")
        self.assertEqual((status, body), (422, {"error": "integrity_error"}))

    # -- concurrency -------------------------------------------------------------

    def test_concurrent_same_key_same_content_single_commit(self):
        records = [sealed_record(f"r{i}") for i in range(3)]
        barrier = threading.Barrier(8)
        results = []

        def submit():
            barrier.wait()
            results.append(self.ingest(records, key="shared-key"))

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        batch_ids = {body["batch_id"] for _, body in results}
        self.assertEqual(len(batch_ids), 1)
        self.assertEqual(self.store_counts(), (1, 3, 3, 1))

    def test_concurrent_same_key_different_content_single_winner(self):
        barrier = threading.Barrier(8)
        results = []

        def submit(index):
            barrier.wait()
            results.append(self.ingest([sealed_record(f"unique-{index}")],
                                       key="contended"))

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 7)
        self.assertTrue(all(body == {"error": "IDEMPOTENCY_CONFLICT"}
                            for status, body in results if status == 409))
        # Only the winner's batch and binding exist.
        self.assertEqual(self.store_counts(), (1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
