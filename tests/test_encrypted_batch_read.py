"""Contract tests for GET /v1/encrypted-records/batches/{batch_id}.

The endpoint reads back a whole client-sealed batch. Tests cover the exact
response shape, persistence across restarts, tenant/format error precedence,
404 opacity across tenants, every batch/record/event integrity mismatch
(422), SQLite failures (503), read-only storage behavior and serial
consistency under concurrent writes.
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
BATCHES_PATH = "/v1/encrypted-records/batches"


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
        self._seq = 0

    def request(self, method, path, body=None, tenant="acme"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.harness.base + path, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def ingest(self, records, tenant="acme"):
        return self.request("POST", INGEST_PATH, {"records": records}, tenant=tenant)

    def get_batch(self, batch_id, tenant="acme", suffix=""):
        return self.request("GET", f"{BATCHES_PATH}/{batch_id}{suffix}", tenant=tenant)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def mutate(self, sql, params=()):
        raw = self.db()
        try:
            with raw:
                raw.execute(sql, params)
        finally:
            raw.close()

    def batch_path_id(self, body):
        return body["batch_id"]

    # -- success shape ------------------------------------------------------

    def test_success_returns_exact_shape_in_submission_order(self):
        records = [
            sealed_record("zeta", metadata={"k": 1}),
            sealed_record("alpha"),
            sealed_record("mid"),
        ]
        status, write_body = self.ingest(records)
        self.assertEqual(status, 201)
        batch_id = write_body["batch_id"]

        raw = self.db()
        try:
            stored_created = raw.execute(
                "SELECT created_at FROM encrypted_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()[0]
        finally:
            raw.close()

        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"batch_id", "count", "created_at", "records"})
        self.assertEqual(body["batch_id"], batch_id)
        self.assertEqual(body["count"], 3)
        self.assertEqual(body["created_at"], stored_created)
        self.assertEqual([r["id"] for r in body["records"]], ["zeta", "alpha", "mid"])
        for index, (record, source) in enumerate(zip(body["records"], records)):
            with self.subTest(index=index):
                self.assertEqual(set(record),
                                 {"id", "algorithm", "key_id", "envelope",
                                  "ciphertext", "metadata"})
                self.assertEqual(record["id"], source["id"])
                self.assertEqual(record["algorithm"], "AES-256-GCM")
                self.assertEqual(record["key_id"], "client-key-1")
                self.assertEqual(record["envelope"], source["envelope"])
                self.assertEqual(record["ciphertext"], source["ciphertext"])
                self.assertEqual(record["metadata"], source["metadata"])

    def test_aes128_and_padded_standard_base64_round_trip(self):
        record = sealed_record(
            "a128",
            algorithm="AES-128-GCM",
            ciphertext={
                "data": b64(b"x"),          # 1 byte -> "eA==" with padding
                "nonce": b64(b"n" * 12),
                "tag": b64(b"t" * 16),
            },
        )
        batch_id = self.ingest([record])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        got = body["records"][0]
        self.assertEqual(got["algorithm"], "AES-128-GCM")
        self.assertEqual(got["envelope"]["wrapped_key"], record["envelope"]["wrapped_key"])
        self.assertEqual(got["ciphertext"]["data"], "eA==")
        self.assertTrue(got["ciphertext"]["data"].endswith("=="))

    def test_empty_ciphertext_data_stays_empty_string(self):
        record = sealed_record("empty")
        record["ciphertext"]["data"] = ""
        batch_id = self.ingest([record])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["records"][0]["ciphertext"]["data"], "")

    def test_absent_key_id_and_metadata_returned_as_null(self):
        record = sealed_record("doc")
        del record["metadata"]
        del record["key_id"]
        batch_id = self.ingest([record])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        got = body["records"][0]
        self.assertIsNone(got["key_id"])
        self.assertIsNone(got["metadata"])

    def test_metadata_restored_as_object_with_values_unchanged(self):
        metadata = {
            "null": None, "bool": True, "neg": -7, "str": "中文内容",
            "frac": 2.5, "nested": {"a": [1, 2, {"b": "c"}]},
        }
        record = sealed_record("doc", metadata=metadata)
        batch_id = self.ingest([record])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["records"][0]["metadata"], metadata)

    def test_single_record_batch(self):
        batch_id = self.ingest([sealed_record("only")])[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 1)
        self.assertEqual([r["id"] for r in body["records"]], ["only"])

    def test_batch_of_100_records_read_back_in_order(self):
        records = [sealed_record(f"id_{i:03d}") for i in range(100)]
        batch_id = self.ingest(records)[1]["batch_id"]
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 100)
        self.assertEqual([r["id"] for r in body["records"]],
                         [f"id_{i:03d}" for i in range(100)])

    def test_multiple_batches_and_tenants_are_independent(self):
        a1 = self.ingest([sealed_record("a1")], tenant="alpha")[1]["batch_id"]
        a2 = self.ingest([sealed_record("a2"), sealed_record("a3")], tenant="alpha")[1]["batch_id"]
        b1 = self.ingest([sealed_record("b1")], tenant="beta")[1]["batch_id"]
        for batch_id, tenant, ids in (
            (a1, "alpha", ["a1"]),
            (a2, "alpha", ["a2", "a3"]),
            (b1, "beta", ["b1"]),
        ):
            status, body = self.get_batch(batch_id, tenant=tenant)
            self.assertEqual(status, 200)
            self.assertEqual([r["id"] for r in body["records"]], ids)

    def test_query_parameters_are_ignored(self):
        batch_id = self.ingest([sealed_record("x")])[1]["batch_id"]
        for suffix in ("?foo=bar", "?limit=999", "?batch_id=batch_" + "0" * 32,
                       "?x=1&y=2", "?"):
            with self.subTest(suffix=suffix):
                status, body = self.get_batch(batch_id, suffix=suffix)
                self.assertEqual(status, 200)
                self.assertEqual(body["batch_id"], batch_id)

    # -- persistence and read-only behavior ---------------------------------

    def test_committed_batch_survives_restart_without_reingest(self):
        records = [sealed_record("r0", metadata={"v": "重启后仍在"}),
                   sealed_record("r1")]
        write_body = self.ingest(records)[1]
        expected = self.get_batch(write_body["batch_id"])[1]

        self.harness.close()
        self._closed_harness = True
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, body = self.get_batch(write_body["batch_id"])
        self.assertEqual(status, 200)
        self.assertEqual(body, expected)

    def test_shape_valid_ciphertext_byte_change_is_returned_verbatim(self):
        record = sealed_record("doc")
        batch_id = self.ingest([record])[1]["batch_id"]
        raw = self.db()
        try:
            blob = bytearray(raw.execute(
                "SELECT ciphertext FROM encrypted_records WHERE id='doc'").fetchone()[0])
            blob[0] ^= 0xFF
            with raw:
                raw.execute("UPDATE encrypted_records SET ciphertext=? WHERE id='doc'",
                            (bytes(blob),))
        finally:
            raw.close()
        status, body = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        # No crypto verification on read: altered but same-length bytes pass.
        self.assertEqual(body["records"][0]["ciphertext"]["data"], b64(bytes(blob)))

    def test_successful_read_does_not_modify_storage(self):
        batch_id = self.ingest([sealed_record("r0"), sealed_record("r1")])[1]["batch_id"]

        def dump():
            raw = self.db()
            try:
                tables = ("encrypted_batches", "encrypted_records",
                          "encrypted_record_events")
                return {
                    name: [tuple(row) for row in raw.execute(
                        f"SELECT * FROM {name} ORDER BY 1,2,3,4")]
                    for name in tables
                }
            finally:
                raw.close()

        before = dump()
        for _ in range(3):
            self.assertEqual(self.get_batch(batch_id)[0], 200)
        self.assertEqual(dump(), before)

    # -- tenant / format error precedence -----------------------------------

    def test_missing_or_invalid_tenant_is_403_with_error_only(self):
        well_formed = "batch_" + "a" * 32
        malformed = "batch_not-an-id"
        for tenant in (None, "bad tenant!", "a/b"):
            for batch_id in (well_formed, malformed):
                with self.subTest(tenant=tenant, batch_id=batch_id):
                    self.assertEqual(self.get_batch(batch_id, tenant=tenant),
                                     (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_malformed_batch_id_is_400_with_error_only(self):
        cases = [
            "",
            "batch_",
            "batch_" + "a" * 31,
            "batch_" + "a" * 33,
            "batch_" + "A" * 32,
            "BATCH_" + "a" * 32,
            "batch_" + "g" * 32,
            "batch_0a1b-2c3d4e5f60718293a4b5c6d7e8f9",
            "a" * 32,
            "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9/extra",
            "../etc",
        ]
        for batch_id in cases:
            with self.subTest(batch_id=batch_id):
                self.assertEqual(self.get_batch(batch_id),
                                 (400, {"error": "invalid_request"}))

    def test_malformed_id_with_garbage_query_still_400(self):
        self.assertEqual(self.get_batch("batch_zzz", suffix="?foo=bar"),
                         (400, {"error": "invalid_request"}))

    def test_unknown_and_cross_tenant_batch_are_opaque_404(self):
        self.assertEqual(self.get_batch("batch_" + "f" * 32),
                         (404, {"error": "not_found"}))
        batch_id = self.ingest([sealed_record("mine")], tenant="alpha")[1]["batch_id"]
        self.assertEqual(self.get_batch(batch_id, tenant="beta"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.get_batch(batch_id, tenant=None),
                         (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_corrupted_foreign_batch_still_404_without_inspecting_details(self):
        # Owner sees integrity damage as 422; another tenant must see a plain
        # 404 even though the same rows are damaged.
        batch_id = self.ingest([sealed_record("r0"), sealed_record("r1")],
                               tenant="alpha")[1]["batch_id"]
        self.mutate("DELETE FROM encrypted_records WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id, tenant="beta"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.get_batch(batch_id, tenant="alpha"),
                         (422, {"error": "integrity_error"}))

    def test_collection_and_wrong_method_keep_404(self):
        self.assertEqual(self.request("GET", BATCHES_PATH),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.request("POST", f"{BATCHES_PATH}/batch_" + "a" * 32),
                         (404, {"error": "not_found"}))

    # -- 422 integrity: batch / record / event consistency ------------------

    def prepare_batch(self, count=2, tenant="acme"):
        # Unique ids per call: integrity subtests share one database and must
        # not collide with ids an earlier subTest already committed.
        seq = self._seq
        self._seq += 1
        records = [sealed_record(f"b{seq}_r{i}") for i in range(count)]
        return self.ingest(records, tenant=tenant)[1]["batch_id"]

    def test_record_count_mismatch_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.assertEqual(self.get_batch(batch_id)[0], 200)
        self.mutate("UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))
        self.assertEqual(self.request("GET", "/health", tenant=None)[0], 200)

    def test_missing_record_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("DELETE FROM encrypted_records WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_extra_record_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate(
            "INSERT INTO encrypted_records (tenant,id,batch_id,position,algorithm,"
            "encryption_key_id,envelope_nonce,wrapped_key,ciphertext,"
            "ciphertext_nonce,tag,metadata) VALUES "
            "('acme','extra',?,2,'AES-256-GCM',NULL,?,?,?,?,?,NULL)",
            (batch_id, b"\x00" * 12, b"\x00" * 48, b"x", b"\x00" * 12, b"\x00" * 16),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_duplicate_displaced_record_positions_are_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET position=0 WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_missing_event_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_extra_event_is_integrity_error(self):
        batch_id = self.prepare_batch()
        raw = self.db()
        try:
            first_id = raw.execute(
                "SELECT id FROM encrypted_records WHERE batch_id=? AND position=0",
                (batch_id,),
            ).fetchone()[0]
        finally:
            raw.close()
        self.mutate(
            "INSERT INTO encrypted_record_events (seq,batch_id,tenant,record_id,position) "
            "SELECT COALESCE(MAX(seq),0)+1,?,'acme',?,2 FROM encrypted_record_events",
            (batch_id, first_id),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_misaligned_event_positions_are_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_record_events SET position=0 WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_event_record_id_mismatch_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate(
            "UPDATE encrypted_record_events SET record_id='r1' "
            "WHERE batch_id=? AND position=0",
            (batch_id,),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_record_associated_with_other_tenant_is_integrity_error(self):
        batch_id = self.prepare_batch()
        # Keep count and positions exactly 0..1; one row is another tenant's.
        self.mutate("DELETE FROM encrypted_records WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.mutate(
            "INSERT INTO encrypted_records (tenant,id,batch_id,position,algorithm,"
            "encryption_key_id,envelope_nonce,wrapped_key,ciphertext,"
            "ciphertext_nonce,tag,metadata) VALUES "
            "('intruder','r1',?,1,'AES-256-GCM',NULL,?,?,?,?,?,NULL)",
            (batch_id, b"\x00" * 12, b"\x00" * 48, b"x", b"\x00" * 12, b"\x00" * 16),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_event_associated_with_other_tenant_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate(
            "UPDATE encrypted_record_events SET tenant='intruder' "
            "WHERE batch_id=? AND position=0",
            (batch_id,),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_batch_count_out_of_bounds_is_integrity_error(self):
        for bad_count in (0, 101, -1):
            with self.subTest(bad_count=bad_count):
                batch_id = self.prepare_batch()
                self.mutate(
                    "UPDATE encrypted_batches SET record_count=? WHERE batch_id=?",
                    (bad_count, batch_id),
                )
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))

    # -- 422 integrity: stored record shape ---------------------------------

    def test_corrupt_metadata_json_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET metadata='{broken' WHERE position=0",)
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_non_object_metadata_is_integrity_error(self):
        for text in ("[1,2]", "5", '"str"', "null", "true"):
            with self.subTest(text=text):
                batch_id = self.prepare_batch()
                self.mutate(
                    "UPDATE encrypted_records SET metadata=? WHERE batch_id=? AND position=0",
                    (text, batch_id),
                )
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))

    def test_oversize_metadata_is_integrity_error(self):
        batch_id = self.prepare_batch()
        oversized = '{"big":"' + ("a" * 16384) + '"}'
        self.mutate(
            "UPDATE encrypted_records SET metadata=? WHERE batch_id=? AND position=0",
            (oversized, batch_id),
        )
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_unsupported_stored_algorithm_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET algorithm='AES-256-CBC' WHERE position=0")
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_wrong_byte_field_lengths_are_integrity_error(self):
        statements = [
            "UPDATE encrypted_records SET envelope_nonce=X'0001' WHERE position=0",
            "UPDATE encrypted_records SET wrapped_key=X'0001' WHERE position=0",
            "UPDATE encrypted_records SET ciphertext_nonce=X'0001' WHERE position=0",
            "UPDATE encrypted_records SET tag=X'0001' WHERE position=0",
            "UPDATE encrypted_records SET ciphertext=? WHERE position=0",
        ]
        for statement in statements:
            with self.subTest(statement=statement):
                batch_id = self.prepare_batch()
                if "?" in statement:
                    self.mutate(statement, (b"x" * 1048577,))
                else:
                    self.mutate(statement)
                self.assertEqual(self.get_batch(batch_id),
                                 (422, {"error": "integrity_error"}))

    def test_invalid_stored_key_id_is_integrity_error(self):
        # An over-long stored key id (an integer would be coerced to TEXT by
        # SQLite's column affinity, so length/shape is the reachable defect).
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET encryption_key_id=? WHERE position=0",
                    ("k" * 129,))
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET encryption_key_id='' WHERE position=0")
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    def test_invalid_stored_identifier_is_integrity_error(self):
        batch_id = self.prepare_batch()
        self.mutate("UPDATE encrypted_records SET id='bad id!' WHERE position=0")
        self.assertEqual(self.get_batch(batch_id),
                         (422, {"error": "integrity_error"}))

    # -- 503 storage ---------------------------------------------------------

    def test_sqlite_read_failures_return_503_and_service_recovers(self):
        batch_id = self.ingest([sealed_record("doc")])[1]["batch_id"]
        self.assertEqual(self.get_batch(batch_id)[0], 200)

        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
            raw.execute("DROP TABLE encrypted_records")
            raw.execute("DROP TABLE encrypted_record_events")
        raw.close()
        self.assertEqual(self.get_batch(batch_id),
                         (503, {"error": "storage_error"}))
        self.assertEqual(self.request("GET", "/health", tenant=None)[0], 200)

        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TABLE encrypted_batches (batch_id TEXT NOT NULL PRIMARY KEY, "
                "tenant TEXT NOT NULL, record_count INTEGER NOT NULL, created_at TEXT NOT NULL)"
            )
            raw.execute(
                "CREATE TABLE encrypted_records (tenant TEXT NOT NULL, id TEXT NOT NULL, "
                "batch_id TEXT NOT NULL, position INTEGER NOT NULL, algorithm TEXT NOT NULL, "
                "encryption_key_id TEXT, envelope_nonce BLOB NOT NULL, wrapped_key BLOB NOT NULL, "
                "ciphertext BLOB NOT NULL, ciphertext_nonce BLOB NOT NULL, tag BLOB, metadata TEXT, "
                "PRIMARY KEY (tenant, id))"
            )
            raw.execute(
                "CREATE TABLE encrypted_record_events (seq INTEGER NOT NULL PRIMARY KEY, "
                "batch_id TEXT NOT NULL, tenant TEXT NOT NULL, record_id TEXT NOT NULL, "
                "position INTEGER NOT NULL)"
            )
        raw.close()

        new_batch = self.ingest([sealed_record("after")])[1]["batch_id"]
        self.assertEqual(self.get_batch(new_batch)[0], 200)
        # The old rows vanished with the dropped tables; the id is simply absent.
        self.assertEqual(self.get_batch(batch_id),
                         (404, {"error": "not_found"}))

    # -- concurrency: complete serial states --------------------------------

    def test_reads_concurrent_with_writes_see_only_complete_batches(self):
        known = []
        known_lock = threading.Lock()
        failures = []
        barrier = threading.Barrier(16)

        def writer(index):
            barrier.wait()
            records = [sealed_record(f"w{index}_r{i}") for i in range(5)]
            status, body = self.ingest(records)
            if status != 201:
                failures.append(("write", status, body))
                return
            with known_lock:
                known.append(body["batch_id"])

        def reader():
            barrier.wait()
            for _ in range(200):
                with known_lock:
                    candidates = list(known)
                for batch_id in candidates:
                    status, body = self.get_batch(batch_id)
                    if status == 404:
                        continue  # committed batches are only read once known
                    if status != 200:
                        failures.append(("read", status, body))
                        continue
                    if body["count"] != len(body["records"]):
                        failures.append(("count", body["count"], len(body["records"])))
                        continue
                    ids = [r["id"] for r in body["records"]]
                    if ids != sorted(ids, key=lambda name: int(name.split("_r")[1])):
                        failures.append(("order", ids))
                    if any(set(r) != {"id", "algorithm", "key_id", "envelope",
                                      "ciphertext", "metadata"} for r in body["records"]):
                        failures.append(("shape", body))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        threads += [threading.Thread(target=reader) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(len(known), 8)
        for batch_id in known:
            status, body = self.get_batch(batch_id)
            self.assertEqual(status, 200)
            self.assertEqual(body["count"], 5)
            self.assertEqual(len(body["records"]), 5)


if __name__ == "__main__":
    unittest.main()
