import base64
import json
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
PATH = "/v1/encrypted-records/batches"


def make_config(directory: Path, active: int = 1) -> Config:
    return Config(directory / "ledger.sqlite3", active, dict(KEY_MATERIAL))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


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


def make_record(
    record_id,
    *,
    envelope=b"ENV-0123456789abcdef0123456789",
    nonce=b"n" * 12,
    body=b"plaintext-body!!",
    algorithm=None,
    metadata="unset",
):
    """Build one structurally valid client-sealed record."""
    record = {
        "id": record_id,
        "algorithm": algorithm if algorithm is not None else {"name": "AES-256-GCM", "key_id": "k-1"},
        "envelope": b64(envelope),
        "nonce": b64(nonce),
        # AES-GCM ciphertext field carries a 16-byte tag in addition to body.
        "ciphertext": b64(body + b"\x00" * 16),
    }
    if metadata != "unset":
        record["metadata"] = metadata
    return record


class EncryptedBatchProtocolTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, body, tenant="acme"):
        headers = {"Content-Type": "application/json"}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        if isinstance(data, str):
            data = data.encode("utf-8")
        request = urllib.request.Request(self.harness.base + PATH, data=data,
                                         headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def submit(self, records, tenant="acme", idempotency_key=None):
        body = {"records": records}
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        return self.request(body, tenant=tenant)

    def db_count(self, table, **where):
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            if where:
                keys, values = zip(*where.items())
                clause = " AND ".join(f"{k}=?" for k in keys)
                return raw.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", values).fetchone()[0]
            return raw.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        finally:
            raw.close()

    # -- success -----------------------------------------------------------

    def test_success_shape_is_201_with_batch_id_count_and_ordered_results(self):
        records = [make_record("r1", body=b"one"), make_record("r2", body="two 内容".encode())]
        status, body = self.submit(records)
        self.assertEqual(status, 201)
        self.assertTrue(body["batch_id"].startswith("bat_"))
        self.assertRegex(body["batch_id"], r"^bat_[A-Za-z0-9_-]+$")
        self.assertEqual(body["tenant"], "acme")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["records"], [
            {"id": "r1", "status": "created"},
            {"id": "r2", "status": "created"},
        ])

    def test_records_persist_in_one_commit_with_verbatim_independent_material(self):
        records = [
            make_record("a", envelope=b"A" * 32, nonce=b"1" * 12, body=b"same"),
            make_record("b", envelope=b"B" * 32, nonce=b"2" * 12, body=b"same"),
        ]
        status, body = self.submit(records)
        self.assertEqual(status, 201)
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 2)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM batch_commits").fetchone()[0], 1)
            rows = {r[0]: r for r in raw.execute(
                "SELECT id, algorithm, envelope, nonce, ciphertext, metadata, batch_id "
                "FROM encrypted_records ORDER BY id")}
        finally:
            raw.close()
        commit_batch_id = body["batch_id"]
        for record_id, envelope, nonce in (("a", b"A" * 32, b"1" * 12),
                                           ("b", b"B" * 32, b"2" * 12)):
            row = rows[record_id]
            self.assertEqual(json.loads(row["algorithm"]), {"name": "AES-256-GCM", "key_id": "k-1"})
            self.assertEqual(base64.b64decode(row["envelope"]), envelope)
            self.assertEqual(bytes(row["nonce"]), nonce)
            self.assertEqual(bytes(row["ciphertext"]), b"same" + b"\x00" * 16)
            self.assertEqual(row["batch_id"], commit_batch_id)
            self.assertIsNone(row["metadata"])
        # Independent envelopes/nonces: nothing was shared or reused.
        self.assertNotEqual(rows["a"]["envelope"], rows["b"]["envelope"])
        self.assertNotEqual(bytes(rows["a"]["nonce"]), bytes(rows["b"]["nonce"]))

    def test_optional_metadata_is_stored(self):
        status, body = self.submit([make_record("m", metadata={"ref": "abc", "n": 3})])
        self.assertEqual(status, 201)
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            stored = raw.execute("SELECT metadata FROM encrypted_records WHERE id='m'").fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(json.loads(stored), {"ref": "abc", "n": 3})

    def test_metadata_absent_vs_null_are_both_accepted(self):
        self.assertEqual(self.submit([make_record("a")])[0], 201)
        record = make_record("b")
        record["metadata"] = None
        self.assertEqual(self.submit([record])[0], 201)

    def test_batch_size_boundaries_accept_100_reject_101(self):
        exact = [make_record(f"id_{i}") for i in range(100)]
        self.assertEqual(self.submit(exact)[0], 201)
        too_many = [make_record(f"other_{i}") for i in range(101)]
        status, body = self.submit(too_many)
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))

    def test_two_batches_get_distinct_batch_ids(self):
        _, first = self.submit([make_record("a")])
        _, second = self.submit([make_record("b")])
        self.assertNotEqual(first["batch_id"], second["batch_id"])

    # -- invalid batch (400 INVALID_BATCH, message locates input) ----------

    def assert_invalid_batch(self, body, location=None, tenant="acme"):
        status, payload = self.request(body, tenant=tenant)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "INVALID_BATCH")
        self.assertIn("message", payload)
        self.assertIsInstance(payload["message"], str)
        self.assertTrue(payload["message"])
        if location is not None:
            self.assertIn(location, payload["message"])

    def test_records_shape_and_size_errors(self):
        self.assert_invalid_batch({}, "records")
        self.assert_invalid_batch({"records": "nope"}, "records")
        self.assert_invalid_batch({"records": []}, "records")
        self.assert_invalid_batch({"records": ["nope"]}, "records[0]")
        self.assert_invalid_batch({"records": [42]}, "records[0]")

    def test_malformed_or_non_object_body_is_invalid_batch(self):
        for raw in ('{"records": [', "not json at all", "42", ["nope"]):
            status, payload = self.request(raw)
            self.assertEqual((status, payload["error"]), (400, "INVALID_BATCH"))
            self.assertIn("message", payload)

    def test_missing_or_invalid_record_id(self):
        base = make_record("ok")
        for field, value in (
            ("id", ""), ("id", "bad.id"), ("id", "x" * 65), ("id", 7), ("id", None),
        ):
            bad = json.loads(json.dumps(base))
            bad["id"] = value
            self.assert_invalid_batch({"records": [bad]}, "records[0].id")
        bad = {k: v for k, v in json.loads(json.dumps(base)).items() if k != "id"}
        self.assert_invalid_batch({"records": [bad]}, "records[0].id")

    def test_missing_or_malformed_envelope_nonce_ciphertext(self):
        base = make_record("ok")
        for field, value in (
            ("envelope", ""), ("envelope", "not base64!!!"), ("envelope", 9),
            ("nonce", ""), ("nonce", "abc!!"), ("nonce", None),
            ("ciphertext", ""), ("ciphertext", "####"), ("ciphertext", 5),
        ):
            bad = json.loads(json.dumps(base))
            bad[field] = value
            self.assert_invalid_batch({"records": [bad]}, f"records[0].{field}")
        for field in ("envelope", "nonce", "ciphertext"):
            bad = {k: v for k, v in json.loads(json.dumps(base)).items() if k != field}
            self.assert_invalid_batch({"records": [bad]}, f"records[0].{field}")

    def test_non_canonical_base64_is_rejected(self):
        bad = make_record("ok")
        # 32 bytes encodes without padding; trim one byte so canonical output
        # has padding, then strip it -> a non-canonical spelling.
        bad["envelope"] = base64.b64encode(b"e" * 31).decode().rstrip("=")
        self.assert_invalid_batch({"records": [bad]}, "records[0].envelope")

    def test_unsupported_or_bad_algorithm_metadata(self):
        base = make_record("ok")
        bad = json.loads(json.dumps(base))
        bad["algorithm"] = {"name": "RSA-OAEP-256"}
        self.assert_invalid_batch({"records": [bad]}, "records[0].algorithm.name")
        for value in ("AES-256-GCM", 42, None, {}):
            bad = json.loads(json.dumps(base))
            bad["algorithm"] = value
            self.assert_invalid_batch({"records": [bad]}, "records[0].algorithm")
        bad = json.loads(json.dumps(base))
        bad["id"] = "k2"
        bad["algorithm"] = {"name": "AES-256-GCM", "key_id": 9}
        self.assert_invalid_batch({"records": [bad]}, "records[0].algorithm.key_id")

    def test_contradictory_fields_are_invalid_batch(self):
        bad = make_record("bad-nonce")
        bad["nonce"] = b64(b"x" * 8)  # AES-256-GCM requires 12 bytes
        self.assert_invalid_batch({"records": [bad]}, "records[0].nonce")
        bad = make_record("bad-tag")
        bad["ciphertext"] = b64(b"\x00" * 7)  # shorter than the 16-byte GCM tag
        self.assert_invalid_batch({"records": [bad]}, "records[0].ciphertext")

    def test_bad_metadata_is_invalid_batch(self):
        bad = make_record("ok")
        bad["metadata"] = "string-not-object"
        self.assert_invalid_batch({"records": [bad]}, "records[0].metadata")
        bad = make_record("ok2")
        bad["metadata"] = [1, 2]
        self.assert_invalid_batch({"records": [bad]}, "records[0].metadata")

    def test_location_points_at_specific_index(self):
        records = [make_record("ok0"), make_record("ok1")]
        records[1]["algorithm"] = {"name": "DES"}
        status, body = self.request({"records": records})
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertTrue(body["message"].startswith("records[1].algorithm"))

    def test_duplicate_ids_in_batch_are_invalid_batch_and_write_nothing(self):
        records = [make_record("dup", body=b"first"), make_record("dup", body=b"second")]
        self.assert_invalid_batch({"records": records}, "records[1].id")
        self.assertEqual(self.db_count("encrypted_records"), 0)
        self.assertEqual(self.db_count("batch_commits"), 0)

    def test_existing_tenant_id_conflict_is_invalid_batch_without_partial_write(self):
        self.assertEqual(self.submit([make_record("old", body=b"kept")])[0], 201)
        records = [make_record("new", body=b"n"), make_record("old", body=b"overwrite")]
        status, body = self.request({"records": records})
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("records[1].id", body["message"])
        # Existing row unchanged, new row invisible.
        self.assertEqual(self.db_count("encrypted_records"), 1)
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            self.assertEqual(bytes(
                raw.execute("SELECT ciphertext FROM encrypted_records WHERE id='old'").fetchone()[0]),
                b"kept" + b"\x00" * 16)
        finally:
            raw.close()

    # -- tenant (403 TENANT_RECORD_FORBIDDEN) ------------------------------

    def test_cross_tenant_record_claim_is_forbidden(self):
        record = make_record("sneaky")
        record["tenant"] = "other-tenant"
        status, body = self.request({"records": [record]}, tenant="acme")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "TENANT_RECORD_FORBIDDEN")
        self.assertIn("records[0].tenant", body["message"])
        self.assertEqual(self.db_count("encrypted_records"), 0)

    def test_missing_or_invalid_tenant_identity_is_forbidden(self):
        for tenant in (None, "bad tenant!", ""):
            status, body = self.request({"records": [make_record("a")]}, tenant=tenant)
            self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"), tenant)

    def test_cross_tenant_attempt_does_not_leak_or_overwrite(self):
        self.assertEqual(self.submit([make_record("only", body=b"alpha")], tenant="alpha")[0], 201)
        # beta cannot overwrite alpha's id, and beta successfully creating the
        # same id later proves tenant rows are independent.
        hostile = make_record("only", body=b"attack")
        hostile["tenant"] = "alpha"
        status, body = self.request({"records": [hostile]}, tenant="beta")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            row = raw.execute(
                "SELECT tenant, ciphertext FROM encrypted_records WHERE id='only'").fetchone()
        finally:
            raw.close()
        self.assertEqual(row["tenant"], "alpha")
        self.assertEqual(bytes(row["ciphertext"]), b"alpha" + b"\x00" * 16)
        self.assertEqual(self.submit([make_record("only", body=b"beta")], tenant="beta")[0], 201)

    def test_malformed_tenant_claim_is_invalid_batch_not_forbidden(self):
        record = make_record("a")
        record["tenant"] = "not a valid ident"
        # A structurally malformed claim fails batch validation; only a
        # well-formed but foreign claim is a 403.
        status, body = self.request({"records": [record]}, tenant="acme")
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))

    # -- tenant isolation ---------------------------------------------------

    def test_same_id_across_tenants_is_independent(self):
        self.assertEqual(self.submit([make_record("shared", body=b"a")], tenant="alpha")[0], 201)
        self.assertEqual(self.submit([make_record("shared", body=b"b")], tenant="beta")[0], 201)
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            tenants = {r[0] for r in raw.execute(
                "SELECT tenant FROM encrypted_records WHERE id='shared'")}
        finally:
            raw.close()
        self.assertEqual(tenants, {"alpha", "beta"})

    # -- atomic write failure (500 BATCH_WRITE_FAILED) ---------------------

    def test_storage_failure_is_500_with_full_rollback(self):
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                        "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END")
        raw.close()

        records = [make_record(f"r{i}") for i in range(5)]
        status, body = self.submit(records)
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "BATCH_WRITE_FAILED")
        self.assertIn("message", body)
        self.assertEqual(self.db_count("encrypted_records"), 0)
        self.assertEqual(self.db_count("batch_commits"), 0)

        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_encrypted_insert")
        raw.close()
        self.assertEqual(self.submit([make_record("after")])[0], 201)

    def test_preexisting_records_survive_failed_batch(self):
        self.assertEqual(self.submit([make_record("kept", body=b"stay")])[0], 201)
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                        "BEGIN SELECT RAISE(ABORT, 'x'); END")
        raw.close()
        self.assertEqual(self.submit([make_record("n1"), make_record("n2")])[0], 500)
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_encrypted_insert")
        raw.close()
        self.assertEqual(self.db_count("encrypted_records"), 1)
        self.assertEqual(
            self.db_count("encrypted_records", id="kept", tenant="acme"), 1)

    # -- idempotency --------------------------------------------------------

    def _idem_record(self, record_id="p1", tag="X"):
        return make_record(record_id, envelope=tag.encode() * 8, body=tag.encode())

    def test_retry_with_same_key_and_payload_returns_same_batch_once(self):
        payload = {"idempotency_key": "tok-1", "records": [self._idem_record()]}
        first_status, first = self.request(payload)
        second_status, second = self.request(json.loads(json.dumps(payload)))
        self.assertEqual(first_status, 201)
        self.assertEqual(second_status, 201)
        self.assertEqual(first["batch_id"], second["batch_id"])
        self.assertEqual(second["idempotency_key"], "tok-1")
        self.assertEqual(self.db_count("encrypted_records"), 1)
        self.assertEqual(self.db_count("batch_commits"), 1)

    def test_same_key_with_different_payload_is_invalid_batch(self):
        self.assertEqual(self.request(
            {"idempotency_key": "tok", "records": [self._idem_record("p1", "A")]})[0], 201)
        status, body = self.request(
            {"idempotency_key": "tok", "records": [self._idem_record("p2", "B")]})
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("idempotency_key", body["message"])
        self.assertEqual(self.db_count("encrypted_records"), 1)

    def test_idempotency_key_is_scoped_per_tenant(self):
        payload_a = {"idempotency_key": "shared-tok", "records": [self._idem_record("p", "A")]}
        status_a, body_a = self.request(payload_a, tenant="alpha")
        # Same token value for a different tenant is a distinct commit.
        payload_b = json.loads(json.dumps(payload_a))
        payload_b["records"][0]["envelope"] = b64(b"B" * 32)
        status_b, body_b = self.request(payload_b, tenant="beta")
        self.assertEqual((status_a, status_b), (201, 201))
        self.assertNotEqual(body_a["batch_id"], body_b["batch_id"])
        self.assertEqual(self.db_count("encrypted_records"), 2)

    def test_invalid_idempotency_key_shape(self):
        for value in ("", "bad token!", "x" * 129, 42, True):
            status, body = self.request(
                {"idempotency_key": value, "records": [self._idem_record(f"i{len(str(value))}")]})
            self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"), value)
        self.assertEqual(self.db_count("encrypted_records"), 0)

    # -- concurrency --------------------------------------------------------

    def test_concurrent_retries_create_exactly_one_batch(self):
        barrier = threading.Barrier(8)
        results = []

        def retry():
            barrier.wait()
            results.append(self.request({
                "idempotency_key": "race-tok",
                "records": [self._idem_record("race", "R")],
            }))

        threads = [threading.Thread(target=retry) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(all(status == 201 for status, _ in results))
        batch_ids = {body["batch_id"] for _, body in results}
        self.assertEqual(len(batch_ids), 1)
        self.assertEqual(self.db_count("encrypted_records"), 1)
        self.assertEqual(self.db_count("batch_commits"), 1)

    def test_concurrent_distinct_batches_same_ids_single_winner_no_partial(self):
        barrier = threading.Barrier(8)
        statuses = []

        def submit_batch():
            barrier.wait()
            statuses.append(self.submit([make_record("race", body=b"x")])[0])

        threads = [threading.Thread(target=submit_batch) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(400), 7)
        self.assertEqual(self.db_count("encrypted_records"), 1)

    # -- compatibility with existing endpoints -----------------------------

    def test_existing_single_record_endpoint_is_unchanged(self):
        # Missing tenant stays 400 invalid_request on the old endpoint, even
        # though the new batch endpoint answers 403 for the same condition.
        request = urllib.request.Request(
            self.harness.base + "/v1/records",
            data=json.dumps({"id": "x", "plaintext": "p"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(request)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            with exc:
                self.assertEqual((exc.code, json.loads(exc.read())),
                                 (400, {"error": "invalid_request"}))

        # Old plaintext batch response shape is untouched.
        request = urllib.request.Request(
            self.harness.base + "/v1/records/batch",
            data=json.dumps({"records": [{"id": "old1", "plaintext": "p"}]}).encode(),
            headers={"Content-Type": "application/json", "X-Tenant-ID": "acme"},
            method="POST")
        with urllib.request.urlopen(request) as response:
            self.assertEqual(json.loads(response.read()),
                             {"key_version": 1, "created": ["old1"]})

    def test_existing_and_encrypted_tables_are_separate(self):
        # An id created through the legacy endpoint does not collide with an
        # encrypted-batch id, and vice versa: they are distinct stores.
        request = urllib.request.Request(
            self.harness.base + "/v1/records",
            data=json.dumps({"id": "same", "plaintext": "legacy"}).encode(),
            headers={"Content-Type": "application/json", "X-Tenant-ID": "acme"},
            method="POST")
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 201)
        self.assertEqual(self.submit([make_record("same", body=b"sealed")])[0], 201)
        self.assertEqual(self.db_count("records", tenant="acme", id="same"), 1)
        self.assertEqual(self.db_count("encrypted_records", tenant="acme", id="same"), 1)


if __name__ == "__main__":
    unittest.main()
