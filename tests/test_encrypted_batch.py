"""Contract tests for the client-encrypted batch ingestion endpoint.

Unlike POST /v1/records (where the server seals plaintext), this ingress stores
records the caller already encrypted. The tests therefore build envelopes with
fixed byte shapes and, in one case, perform real client-side AES-GCM sealing and
offline recovery straight from the SQLite rows.
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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cipher_ledger.config import Config
from cipher_ledger.database import connect
from cipher_ledger.server import LedgerServer

KEY_MATERIAL = {v: bytes([v]) * 16 + bytes([100 + v]) * 16 for v in (1, 2, 3)}
ENCRYPTED_PATH = "/v1/encrypted-records/batch"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def make_config(directory: Path, active: int = 1, versions=(1, 2, 3)) -> Config:
    return Config(
        directory / "ledger.sqlite3",
        active,
        {v: KEY_MATERIAL[v] for v in versions},
    )


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


class EncryptedBatchTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, body, tenant="acme", path=ENCRYPTED_PATH):
        headers = {"Content-Type": "application/json"}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        if isinstance(body, (bytes, str)):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
        else:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.harness.base + path, data=data,
                                         headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def ingest(self, records, tenant="acme"):
        return self.request({"records": records}, tenant=tenant)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def assert_invalid_batch(self, result, location):
        status, body = result
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        self.assertIn(location, body["message"])

    # -- success -----------------------------------------------------------

    def test_success_returns_batch_id_count_and_ordered_results(self):
        records = [sealed_record("alpha"), sealed_record("beta"), sealed_record("gamma")]
        status, body = self.ingest(records)
        self.assertEqual(status, 201)
        self.assertTrue(body["batch_id"].startswith("batch_"))
        self.assertEqual(len(body["batch_id"]), len("batch_") + 32)
        self.assertEqual(body["count"], 3)
        self.assertEqual(
            body["results"],
            [
                {"id": "alpha", "status": "created"},
                {"id": "beta", "status": "created"},
                {"id": "gamma", "status": "created"},
            ],
        )

    def test_results_follow_input_order_not_id_order(self):
        records = [sealed_record("zeta"), sealed_record("alpha"), sealed_record("mid")]
        status, body = self.ingest(records)
        self.assertEqual(status, 201)
        self.assertEqual([r["id"] for r in body["results"]], ["zeta", "alpha", "mid"])

    def test_records_events_and_batch_row_commit_together(self):
        records = [sealed_record("r0"), sealed_record("r1")]
        status, body = self.ingest(records)
        self.assertEqual(status, 201)
        batch_id = body["batch_id"]
        raw = self.db()
        try:
            self.assertEqual(
                tuple(raw.execute(
                    "SELECT batch_id, tenant, record_count FROM encrypted_batches"
                ).fetchone()),
                (batch_id, "acme", 2),
            )
            rows = raw.execute(
                "SELECT id, position, batch_id FROM encrypted_records ORDER BY position"
            ).fetchall()
            self.assertEqual([tuple(r) for r in rows],
                             [("r0", 0, batch_id), ("r1", 1, batch_id)])
            events = raw.execute(
                "SELECT batch_id, tenant, record_id, position "
                "FROM encrypted_record_events ORDER BY seq"
            ).fetchall()
            self.assertEqual([tuple(e) for e in events],
                             [(batch_id, "acme", "r0", 0), (batch_id, "acme", "r1", 1)])
        finally:
            raw.close()

    def test_envelope_bytes_stored_verbatim_with_metadata_and_key_id(self):
        record = sealed_record("doc", key_id="k-9", metadata={"a": 1, "zh": "内容"})
        self.assertEqual(self.ingest([record])[0], 201)
        raw = self.db()
        try:
            row = raw.execute(
                "SELECT algorithm, encryption_key_id, envelope_nonce, wrapped_key, "
                "ciphertext, ciphertext_nonce, tag, metadata FROM encrypted_records"
            ).fetchone()
        finally:
            raw.close()
        self.assertEqual(row["algorithm"], "AES-256-GCM")
        self.assertEqual(row["encryption_key_id"], "k-9")
        self.assertEqual(base64.b64decode(record["envelope"]["nonce"]),
                         bytes(row["envelope_nonce"]))
        self.assertEqual(base64.b64decode(record["envelope"]["wrapped_key"]),
                         bytes(row["wrapped_key"]))
        self.assertEqual(base64.b64decode(record["ciphertext"]["data"]),
                         bytes(row["ciphertext"]))
        self.assertEqual(base64.b64decode(record["ciphertext"]["nonce"]),
                         bytes(row["ciphertext_nonce"]))
        self.assertEqual(base64.b64decode(record["ciphertext"]["tag"]), bytes(row["tag"]))
        self.assertEqual(json.loads(row["metadata"]), {"a": 1, "zh": "内容"})

    def test_optional_metadata_and_key_id_default_to_null(self):
        record = sealed_record("doc")
        del record["metadata"]
        del record["key_id"]
        self.assertEqual(self.ingest([record])[0], 201)
        raw = self.db()
        try:
            row = raw.execute(
                "SELECT encryption_key_id, metadata FROM encrypted_records"
            ).fetchone()
        finally:
            raw.close()
        self.assertIsNone(row["encryption_key_id"])
        self.assertIsNone(row["metadata"])

    def test_each_record_uses_independent_envelope_and_nonces(self):
        records = [sealed_record("a"), sealed_record("b")]
        self.assertEqual(self.ingest(records)[0], 201)
        raw = self.db()
        try:
            rows = {r["id"]: tuple(r) for r in raw.execute(
                "SELECT id, envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag "
                "FROM encrypted_records")}
        finally:
            raw.close()
        for column in range(1, 6):
            self.assertNotEqual(rows["a"][column], rows["b"][column])

    def test_client_sealed_envelope_is_recoverable_offline(self):
        # Real client-side sealing: the server never sees the plaintext or keys.
        client_kek = os.urandom(32)
        data_key = os.urandom(32)
        tenant, record_id, plaintext = "acme", "sealed", "离线可恢复的密文 🔐"
        body_nonce, wrap_nonce = os.urandom(12), os.urandom(12)
        body_aad = json.dumps([1, tenant, record_id], separators=(",", ":")).encode()
        wrap_aad = json.dumps([1, tenant, record_id, "client-key-1"],
                              separators=(",", ":")).encode()
        sealed = AESGCM(data_key).encrypt(body_nonce, plaintext.encode(), body_aad)
        wrapped = AESGCM(client_kek).encrypt(wrap_nonce, data_key, wrap_aad)
        record = {
            "id": record_id,
            "algorithm": "AES-256-GCM",
            "key_id": "client-key-1",
            "envelope": {"nonce": b64(wrap_nonce), "wrapped_key": b64(wrapped)},
            "ciphertext": {
                "data": b64(sealed[:-16]),
                "nonce": b64(body_nonce),
                "tag": b64(sealed[-16:]),
            },
        }
        self.assertEqual(self.ingest([record])[0], 201)
        raw = self.db()
        try:
            row = raw.execute(
                "SELECT envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag "
                "FROM encrypted_records WHERE id=?", (record_id,)
            ).fetchone()
        finally:
            raw.close()
        recovered_key = AESGCM(client_kek).decrypt(
            bytes(row["envelope_nonce"]), bytes(row["wrapped_key"]), wrap_aad)
        recovered = AESGCM(recovered_key).decrypt(
            bytes(row["ciphertext_nonce"]),
            bytes(row["ciphertext"]) + bytes(row["tag"]), body_aad)
        self.assertEqual(recovered.decode(), plaintext)

    def test_empty_ciphertext_body_accepted(self):
        record = sealed_record("empty")
        record["ciphertext"]["data"] = ""  # empty plaintext -> GCM emits only tag
        self.assertEqual(self.ingest([record])[0], 201)

    def test_size_boundaries_accept_100_reject_101(self):
        exact = [sealed_record(f"id_{i:03d}") for i in range(100)]
        self.assertEqual(self.ingest(exact)[0], 201)
        too_many = [sealed_record(f"x_{i:03d}") for i in range(101)]
        self.assert_invalid_batch(self.ingest(too_many), "records")

    def test_two_batches_get_distinct_ids(self):
        first = self.ingest([sealed_record("a")])[1]["batch_id"]
        second = self.ingest([sealed_record("b")])[1]["batch_id"]
        self.assertNotEqual(first, second)

    # -- validation: shape -------------------------------------------------

    def test_body_level_failures(self):
        self.assert_invalid_batch(self.request([{"records": []}]), "body")
        self.assert_invalid_batch(self.request("not json"), "body")
        self.assert_invalid_batch(self.request('{"records":['), "body")
        self.assert_invalid_batch(self.request({}), "records")
        self.assert_invalid_batch(self.request({"records": "nope"}), "records")
        self.assert_invalid_batch(self.request({"records": []}), "records")

    def test_item_must_be_object_with_location(self):
        self.assert_invalid_batch(self.ingest(["nope"]), "records[0]")
        self.assert_invalid_batch(self.ingest([sealed_record("ok"), 5]), "records[1]")

    def test_invalid_record_ids_point_to_location(self):
        cases = [
            ("missing", {}),
            ("wrong type", {"id": 7}),
            ("empty", {"id": ""}),
            ("bad chars", {"id": "bad.id"}),
            ("too long", {"id": "x" * 65}),
        ]
        base = sealed_record("placeholder")
        for label, override in cases:
            with self.subTest(label):
                record = dict(base)
                if label == "missing":
                    del record["id"]
                else:
                    record.update(override)
                self.assert_invalid_batch(self.ingest([record]), "records[0].id")

    def test_unsupported_algorithm(self):
        for bad in ("AES-256-CBC", "aes-256-gcm", "", 3, None):
            with self.subTest(bad=bad):
                record = sealed_record("a", algorithm="AES-256-GCM")
                record["algorithm"] = bad
                self.assert_invalid_batch(self.ingest([record]), "records[0].algorithm")

    def test_algorithm_field_contradiction_wrapped_key_length(self):
        # Declares AES-128 (16-byte key -> 32-byte wrapped) but supplies 48.
        record = sealed_record("a", algorithm="AES-128-GCM")
        record["envelope"]["wrapped_key"] = b64(os.urandom(48))
        self.assert_invalid_batch(self.ingest([record]),
                                  "records[0].envelope.wrapped_key")
        # Declares AES-256 (48-byte wrapped) but supplies 32.
        record = sealed_record("b", algorithm="AES-256-GCM")
        record["envelope"]["wrapped_key"] = b64(os.urandom(32))
        self.assert_invalid_batch(self.ingest([record]),
                                  "records[0].envelope.wrapped_key")

    def test_aes128_accepted_with_correct_lengths(self):
        record = sealed_record("a", algorithm="AES-128-GCM")
        self.assertEqual(self.ingest([record])[0], 201)

    def test_envelope_field_validation(self):
        good = sealed_record("a")
        bad_envelope = [
            ("missing", {}, "records[0].envelope.nonce"),
            ("non-object", [], "records[0].envelope"),
            ("nonce missing", {"wrapped_key": good["envelope"]["wrapped_key"]},
             "records[0].envelope.nonce"),
            ("nonce bad base64", {"nonce": "!!!", "wrapped_key": good["envelope"]["wrapped_key"]},
             "records[0].envelope.nonce"),
            ("nonce wrong length", {"nonce": b64(b"short"),
                                    "wrapped_key": good["envelope"]["wrapped_key"]},
             "records[0].envelope.nonce"),
            ("wrapped missing", {"nonce": good["envelope"]["nonce"]},
             "records[0].envelope.wrapped_key"),
            ("wrapped bad base64", {"nonce": good["envelope"]["nonce"], "wrapped_key": "@@@"},
             "records[0].envelope.wrapped_key"),
            ("wrapped wrong length", {"nonce": good["envelope"]["nonce"],
                                      "wrapped_key": b64(b"x" * 12)},
             "records[0].envelope.wrapped_key"),
        ]
        for label, envelope, location in bad_envelope:
            with self.subTest(label):
                record = sealed_record("a")
                record["envelope"] = envelope
                self.assert_invalid_batch(self.ingest([record]), location)

    def test_ciphertext_field_validation(self):
        good = sealed_record("a")
        cases = [
            ("missing", {}, "records[0].ciphertext"),
            ("non-object", [], "records[0].ciphertext"),
            ("data missing", {"nonce": good["ciphertext"]["nonce"],
                              "tag": good["ciphertext"]["tag"]},
             "records[0].ciphertext.data"),
            ("data bad base64", {"data": "nope!", "nonce": good["ciphertext"]["nonce"],
                                 "tag": good["ciphertext"]["tag"]},
             "records[0].ciphertext.data"),
            ("data too large", {"data": b64(b"x" * 1048577),
                                "nonce": good["ciphertext"]["nonce"],
                                "tag": good["ciphertext"]["tag"]},
             "records[0].ciphertext.data"),
            ("nonce wrong length", {"data": good["ciphertext"]["data"],
                                    "nonce": b64(b"short"),
                                    "tag": good["ciphertext"]["tag"]},
             "records[0].ciphertext.nonce"),
            ("tag missing", {"data": good["ciphertext"]["data"],
                             "nonce": good["ciphertext"]["nonce"]},
             "records[0].ciphertext.tag"),
            ("tag wrong length", {"data": good["ciphertext"]["data"],
                                  "nonce": good["ciphertext"]["nonce"],
                                  "tag": b64(b"short")},
             "records[0].ciphertext.tag"),
        ]
        for label, cipher, location in cases:
            with self.subTest(label):
                record = sealed_record("a")
                record["ciphertext"] = cipher
                self.assert_invalid_batch(self.ingest([record]), location)

    def test_metadata_and_key_id_validation(self):
        record = sealed_record("a")
        record["metadata"] = "not-object"
        self.assert_invalid_batch(self.ingest([record]), "records[0].metadata")
        record = sealed_record("a")
        record["metadata"] = {"big": "x" * 16384}
        self.assert_invalid_batch(self.ingest([record]), "records[0].metadata")
        record = sealed_record("a")
        record["key_id"] = 42
        self.assert_invalid_batch(self.ingest([record]), "records[0].key_id")
        record = sealed_record("a")
        record["key_id"] = "k" * 129
        self.assert_invalid_batch(self.ingest([record]), "records[0].key_id")

    def test_error_points_at_first_invalid_index(self):
        records = [sealed_record("ok0"), sealed_record("ok1"),
                   sealed_record("bad"), sealed_record("ok3")]
        records[2]["id"] = "bad id!"
        self.assert_invalid_batch(self.ingest(records), "records[2].id")

    def test_invalid_batch_writes_nothing(self):
        records = [sealed_record("ok"), sealed_record("bad")]
        records[1]["ciphertext"]["tag"] = b64(b"short")
        self.assert_invalid_batch(self.ingest(records), "records[1].ciphertext.tag")
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 0)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 0)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0], 0)
        finally:
            raw.close()

    # -- conflicts: all INVALID_BATCH, atomic ------------------------------

    def test_duplicate_id_in_batch_is_invalid_batch_without_writes(self):
        records = [sealed_record("dup"), sealed_record("other"), sealed_record("dup")]
        status, body = self.ingest(records)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        self.assertIn("records[2].id", body["message"])
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 0)
        finally:
            raw.close()

    def test_existing_same_tenant_id_is_invalid_batch_and_keeps_old_value(self):
        first = sealed_record("old")
        self.assertEqual(self.ingest([first])[0], 201)
        second = [sealed_record("new"), sealed_record("old")]
        status, body = self.ingest(second)
        self.assertEqual((status, body["error"]), (400, "INVALID_BATCH"))
        self.assertIn("records[1].id", body["message"])
        raw = self.db()
        try:
            ids = {r[0] for r in raw.execute("SELECT id FROM encrypted_records")}
            self.assertEqual(ids, {"old"})
            stored = raw.execute(
                "SELECT ciphertext FROM encrypted_records WHERE id='old'").fetchone()[0]
        finally:
            raw.close()
        # The existing envelope bytes are untouched.
        self.assertEqual(bytes(stored), base64.b64decode(first["ciphertext"]["data"]))

    def test_duplicate_and_existing_conflict_use_same_error_code(self):
        self.assertEqual(self.ingest([sealed_record("x")])[0], 201)
        dup = self.ingest([sealed_record("d"), sealed_record("d")])
        existing = self.ingest([sealed_record("x")])
        self.assertEqual((dup[0], dup[1]["error"]), (400, "INVALID_BATCH"))
        self.assertEqual((existing[0], existing[1]["error"]), (400, "INVALID_BATCH"))

    def test_retry_after_failure_does_not_duplicate(self):
        bad = [sealed_record("a"), sealed_record("b")]
        bad[1]["id"] = "a"  # in-batch duplicate
        self.assertEqual(self.ingest(bad)[0], 400)
        good = [sealed_record("a"), sealed_record("b")]
        status, body = self.ingest(good)
        self.assertEqual(status, 201)
        self.assertEqual(body["count"], 2)
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 2)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 1)
        finally:
            raw.close()

    # -- tenant authorization ----------------------------------------------

    def test_missing_or_invalid_tenant_identity_is_forbidden(self):
        record = sealed_record("a")
        for tenant in (None, "bad tenant!", "a/b"):
            with self.subTest(tenant=tenant):
                status, body = self.ingest([record], tenant=tenant)
                self.assertEqual(status, 403)
                self.assertEqual(body["error"], "TENANT_RECORD_FORBIDDEN")
                self.assertIn("identity", body["message"])

    def test_record_claiming_another_tenant_is_forbidden(self):
        record = sealed_record("a")
        record["tenant"] = "other"
        status, body = self.ingest([record], tenant="acme")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))
        self.assertIn("records[0].tenant", body["message"])

    def test_cross_tenant_claim_takes_precedence_over_shape(self):
        # Malformed in other ways, but the tenant claim is the binding decision.
        record = {"id": 7, "tenant": "other", "algorithm": "BOGUS"}
        status, body = self.ingest([record], tenant="acme")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))

    def test_later_record_cross_tenant_is_forbidden(self):
        records = [sealed_record("ok0"), sealed_record("ok1")]
        records[1]["tenant"] = "intruder"
        self.assertEqual(self.ingest(records)[0], 403)

    def test_matching_tenant_claim_accepted(self):
        record = sealed_record("a")
        record["tenant"] = "acme"
        self.assertEqual(self.ingest([record], tenant="acme")[0], 201)

    def test_same_id_in_other_tenant_is_independent(self):
        self.assertEqual(self.ingest([sealed_record("shared")], tenant="alpha")[0], 201)
        self.assertEqual(self.ingest([sealed_record("shared")], tenant="beta")[0], 201)
        raw = self.db()
        try:
            tenants = {r[0] for r in raw.execute(
                "SELECT tenant FROM encrypted_records WHERE id='shared'")}
        finally:
            raw.close()
        self.assertEqual(tenants, {"alpha", "beta"})

    # -- storage failure: atomic rollback, 500 -----------------------------

    def test_storage_failure_rolls_back_everything(self):
        raw = self.db()
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                        "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END")
        raw.close()
        records = [sealed_record(f"r{i}") for i in range(5)]
        status, body = self.ingest(records)
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 0)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 0)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0], 0)
        finally:
            raw.close()

    def test_ledger_append_failure_rolls_back_records(self):
        # Records insert fine but the append-only ledger rejects: still atomic.
        raw = self.db()
        with raw:
            raw.execute("CREATE TRIGGER block_event_append BEFORE INSERT ON encrypted_record_events "
                        "BEGIN SELECT RAISE(ABORT, 'ledger frozen'); END")
        raw.close()
        status, body = self.ingest([sealed_record("a"), sealed_record("b")])
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 0)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 0)
        finally:
            raw.close()

    def test_existing_records_survive_failed_batch(self):
        self.assertEqual(self.ingest([sealed_record("keep")])[0], 201)
        raw = self.db()
        with raw:
            raw.execute("CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                        "BEGIN SELECT RAISE(ABORT, 'no'); END")
        raw.close()
        self.assertEqual(self.ingest([sealed_record("nope")])[0], 500)
        raw = self.db()
        try:
            ids = {r[0] for r in raw.execute("SELECT id FROM encrypted_records")}
        finally:
            raw.close()
        self.assertEqual(ids, {"keep"})

    # -- concurrency -------------------------------------------------------

    def test_concurrent_batches_same_ids_single_winner_no_duplicates(self):
        barrier = threading.Barrier(8)
        results = []

        def submit():
            barrier.wait()
            results.append(self.ingest([sealed_record(f"r{i}") for i in range(3)]))

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(400), 7)
        self.assertTrue(all(body["error"] == "INVALID_BATCH"
                            for status, body in results if status == 400))
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 3)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0], 3)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 1)
        finally:
            raw.close()

    # -- compatibility -----------------------------------------------------

    def test_existing_single_and_plaintext_batch_endpoints_unchanged(self):
        status, body = self.request(
            {"id": "p1", "plaintext": "原文"}, tenant="acme", path="/v1/records")
        self.assertEqual((status, body), (201, {"id": "p1", "key_version": 1}))
        status, body = self.request(
            {"records": [{"id": "p2", "plaintext": "批量原文"}]},
            tenant="acme", path="/v1/records/batch")
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["p2"]}))
        # Plaintext and encrypted stores are separate and tenant-bound.
        raw = self.db()
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 2)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 0)
        finally:
            raw.close()

    def test_unknown_route_still_404(self):
        status, body = self.request({"records": []}, path="/v1/encrypted-records")
        self.assertEqual((status, body), (404, {"error": "not_found"}))


if __name__ == "__main__":
    unittest.main()
