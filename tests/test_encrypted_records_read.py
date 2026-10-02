"""Contract tests for POST /v1/encrypted-records/batch/read.

The endpoint fetches client-sealed records by id across batches for one
tenant. Success shape and ordering, error precedence (403 before body, 404
before batch detail), whole-batch integrity re-validation of every involved
batch -- including its unrequested records -- and serial visibility under
concurrency are all exercised here; most tampering is done directly on the
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

    def read_by_ids(self, ids, tenant="acme", query=""):
        suffix = f"?{query}" if query else ""
        return self.request(
            "POST", READ_PATH + suffix, {"ids": ids}, tenant=tenant
        )

    def read_raw(self, raw_body, tenant="acme"):
        return self.request("POST", READ_PATH, raw_body, tenant=tenant)

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

    def batch_created_at(self, batch_id):
        raw = self.db()
        try:
            return raw.execute(
                "SELECT created_at FROM encrypted_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()[0]
        finally:
            raw.close()

    # -- success -----------------------------------------------------------

    def test_items_returned_in_request_order_across_batches(self):
        records_a = [sealed_record("a"), sealed_record("b")]
        records_b = [sealed_record("c")]
        records_c = [sealed_record("d"), sealed_record("e")]
        batch_a = self.ingest(records_a)[1]["batch_id"]
        batch_b = self.ingest(records_b)[1]["batch_id"]
        batch_c = self.ingest(records_c)[1]["batch_id"]

        status, body = self.read_by_ids(["d", "a", "c", "e", "b"])
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 5)
        self.assertEqual([item["id"] for item in body["items"]],
                         ["d", "a", "c", "e", "b"])
        expected_batch = {
            "a": batch_a, "b": batch_a, "c": batch_b, "d": batch_c, "e": batch_c,
        }
        for item in body["items"]:
            self.assertEqual(item["batch_id"], expected_batch[item["id"]])
            self.assertEqual(item["created_at"], self.batch_created_at(item["batch_id"]))
            self.assertEqual(
                set(item),
                {"id", "algorithm", "key_id", "envelope", "ciphertext",
                 "metadata", "batch_id", "created_at"},
            )

    def test_item_record_shape_matches_whole_batch_read(self):
        source = sealed_record("zeta")
        batch_id = self.ingest([source])[1]["batch_id"]
        _, whole = self.get_batch(batch_id)
        _, body = self.read_by_ids(["zeta"])
        item = body["items"][0]
        for field in ("id", "algorithm", "key_id", "envelope", "ciphertext", "metadata"):
            self.assertEqual(item[field], whole["records"][0][field])
        self.assertEqual(item["batch_id"], batch_id)
        self.assertEqual(item["created_at"], whole["created_at"])

    def test_multiple_ids_from_one_batch_and_repeated_batches(self):
        batch_one = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        batch_two = self.ingest([sealed_record("c")])[1]["batch_id"]
        status, body = self.read_by_ids(["b", "a", "c"])
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["batch_id"] for item in body["items"]],
            [batch_one, batch_one, batch_two],
        )

    def test_only_requested_records_are_returned(self):
        self.ingest([sealed_record(f"r{i}") for i in range(5)])
        _, body = self.read_by_ids(["r3", "r0"])
        self.assertEqual(body["count"], 2)
        self.assertEqual([item["id"] for item in body["items"]], ["r3", "r0"])

    def test_base64_empty_ciphertext_nulls_and_metadata_rules(self):
        record = sealed_record("doc")
        record["ciphertext"]["data"] = ""
        del record["key_id"]
        del record["metadata"]
        self.ingest([record])
        _, body = self.read_by_ids(["doc"])
        item = body["items"][0]
        self.assertEqual(item["ciphertext"]["data"], "")
        self.assertIsNone(item["key_id"])
        self.assertIsNone(item["metadata"])
        self.assertTrue(item["ciphertext"]["tag"].endswith("=="))
        for value in (item["envelope"]["nonce"], item["envelope"]["wrapped_key"],
                      item["ciphertext"]["nonce"], item["ciphertext"]["tag"]):
            self.assertEqual(value, b64(base64.b64decode(value)))

    def test_metadata_values_round_trip_unchanged(self):
        metadata = {"nested": {"b": [1, 2, {"c": "中文"}]}, "n": None, "t": True, "f": 3.5}
        self.ingest([sealed_record("doc", metadata=metadata)])
        _, body = self.read_by_ids(["doc"])
        self.assertEqual(body["items"][0]["metadata"], metadata)

    def test_aes128_records_read_across_batches(self):
        self.ingest([sealed_record("g")])
        record = sealed_record("h", algorithm="AES-128-GCM")
        self.ingest([record])
        _, body = self.read_by_ids(["h", "g"])
        self.assertEqual([item["algorithm"] for item in body["items"]],
                         ["AES-128-GCM", "AES-256-GCM"])
        self.assertEqual(body["items"][0]["envelope"]["wrapped_key"],
                         record["envelope"]["wrapped_key"])

    def test_batch_of_100_distinct_ids_reads_in_order(self):
        records = [sealed_record(f"id_{i:03d}") for i in range(50)]
        records += [sealed_record(f"jd_{i:03d}") for i in range(50)]
        self.ingest(records[:50])
        self.ingest(records[50:])
        ids = [record["id"] for record in records]
        status, body = self.read_by_ids(ids)
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 100)
        self.assertEqual([item["id"] for item in body["items"]], ids)

    def test_extra_body_fields_and_query_parameters_are_ignored(self):
        self.ingest([sealed_record("a")])
        for query in ("foo=bar", "limit=999", "x=1&ids=spoof", "="):
            with self.subTest(query=query):
                status, body = self.request(
                    "POST", f"{READ_PATH}?{query}",
                    {"ids": ["a"], "extra": [1, 2], "other": {"nested": True}},
                )
                self.assertEqual(status, 200)
                self.assertEqual(body["count"], 1)

    def test_records_survive_restart_and_read_does_not_rewrite(self):
        records = [sealed_record("r0"), sealed_record("r1")]
        batch_id = self.ingest(records)[1]["batch_id"]
        before = self.read_by_ids(["r1", "r0"])[1]

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.read_by_ids(["r1", "r0"])
        self.assertEqual(status, 200)
        self.assertEqual(after, before)
        self.assertEqual(after["items"][0]["batch_id"], batch_id)

    def test_read_does_not_modify_storage(self):
        self.ingest([sealed_record("a")])
        self.ingest([sealed_record("b")])
        raw = self.db()
        try:
            counts_before = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
            )
        finally:
            raw.close()
        for _ in range(3):
            self.assertEqual(self.read_by_ids(["b", "a"])[0], 200)
        raw = self.db()
        try:
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
        self.assertEqual(counts_after, counts_before)

    # -- tenant and request validation -------------------------------------

    def test_missing_or_invalid_tenant_is_forbidden_before_body(self):
        bad_bodies = (b"not json at all", b"\xff\xfe", b"[]", b"null",
                      json.dumps({"ids": ["a", "a"]}).encode())
        for tenant in (None, "bad tenant!", "a/b", ""):
            for raw in bad_bodies:
                with self.subTest(tenant=tenant, raw=raw[:8]):
                    self.assertEqual(
                        self.read_raw(raw, tenant=tenant),
                        (403, {"error": "TENANT_RECORD_FORBIDDEN"}),
                    )

    def test_body_must_be_a_utf8_json_object(self):
        for raw in (b"", b"not json", b"\xff\xfe", b"[1,2]", b'"x"', b"null", b"42"):
            with self.subTest(raw=raw):
                self.assertEqual(self.read_raw(raw),
                                 (400, {"error": "invalid_request"}))

    def test_ids_shape_failures_are_invalid_request(self):
        cases = [
            {},
            {"ids": "x"},
            {"ids": None},
            {"ids": []},
            {"ids": ["x"] * 101},
            {"ids": [1]},
            {"ids": [None]},
            {"ids": [["x"]]},
            {"ids": [""]},
            {"ids": ["bad id"]},
            {"ids": ["a/b"]},
            {"ids": ["x" * 65]},
            {"ids": ["a", "a"]},
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", READ_PATH, body),
                                 (400, {"error": "invalid_request"}))

    def test_boundary_counts_one_and_one_hundred_accepted(self):
        records = [sealed_record(f"n{i}") for i in range(100)]
        self.ingest(records[:50])
        self.ingest(records[50:])
        self.assertEqual(self.read_by_ids(["n0"])[0], 200)
        status, body = self.read_by_ids([f"n{i}" for i in range(100)])
        self.assertEqual((status, body["count"]), (200, 100))

    # -- 404 precedence -----------------------------------------------------

    def test_unknown_id_is_not_found_with_bare_error_body(self):
        status, body = self.read_by_ids(["ghost"])
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_foreign_tenant_same_named_id_is_not_found(self):
        self.ingest([sealed_record("shared")], tenant="alpha")
        self.assertEqual(self.read_by_ids(["shared"], tenant="beta"),
                         (404, {"error": "not_found"}))
        # Even when beta also has a plaintext record of the same id.
        self.request("POST", "/v1/records",
                     {"id": "shared", "plaintext": "p"}, tenant="beta")
        self.assertEqual(self.read_by_ids(["shared"], tenant="beta"),
                         (404, {"error": "not_found"}))

    def test_plaintext_record_same_id_is_not_found(self):
        self.request("POST", "/v1/records",
                     {"id": "doc", "plaintext": "secret"})
        self.assertEqual(self.read_by_ids(["doc"]),
                         (404, {"error": "not_found"}))

    def test_one_missing_id_fails_whole_request_without_partial_items(self):
        self.ingest([sealed_record("a")])
        status, body = self.read_by_ids(["a", "missing"])
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_missing_id_takes_precedence_over_corrupt_batch(self):
        # The involved batch is badly damaged (event gone), but the request
        # also names an absent id; existence is decided first, so it stays 404.
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        self.tamper("DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
                    (batch_id,))
        self.assertEqual(self.read_by_ids(["a", "ghost"]),
                         (404, {"error": "not_found"}))

    # -- 422 integrity review of involved batches --------------------------

    def test_associated_batch_row_missing_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        self.tamper("DELETE FROM encrypted_batches WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))

    def test_associated_batch_owned_by_another_tenant_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a")])[1]["batch_id"]
        self.tamper("UPDATE encrypted_batches SET tenant='intruder' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))

    def test_illegal_stored_batch_id_link_is_integrity_error(self):
        self.ingest([sealed_record("a")])
        self.tamper("UPDATE encrypted_records SET batch_id='not-a-batch' WHERE id='a'")
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))

    def test_record_count_drift_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        for count in (0, 3, 101, "two"):
            self.tamper("UPDATE encrypted_batches SET record_count=? WHERE batch_id=?",
                        (count, batch_id))
            with self.subTest(count=count):
                self.assertEqual(self.read_by_ids(["a"]),
                                 (422, {"error": "integrity_error"}))

    def test_unrequested_record_of_involved_batch_still_validated(self):
        batch_id = self.ingest(
            [sealed_record("a"), sealed_record("b"), sealed_record("c")]
        )[1]["batch_id"]

        # An unrequested record row disappears: positions 0 and 2 remain.
        self.tamper("DELETE FROM encrypted_records WHERE batch_id=? AND id='b'",
                    (batch_id,))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))

        # Restore the row but damage an unrequested record's metadata.
        self.tamper(
            "INSERT INTO encrypted_records "
            "(tenant, id, batch_id, position, algorithm, encryption_key_id, "
            "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata) "
            "SELECT tenant, 'b', batch_id, 1, algorithm, encryption_key_id, "
            "envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata "
            "FROM encrypted_records WHERE id='a'"
        )
        self.tamper("UPDATE encrypted_records SET metadata='not json' WHERE id='c'")
        self.assertEqual(self.read_by_ids(["a", "b"]),
                         (422, {"error": "integrity_error"}))

    def test_unrequested_record_event_drift_is_integrity_error(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        # Remove the event of the record the caller did NOT ask for.
        self.tamper("DELETE FROM encrypted_record_events WHERE batch_id=? AND record_id='b'",
                    (batch_id,))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))

    def test_event_misplaced_mismatched_and_cross_tenant(self):
        batch_id = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        self.tamper("UPDATE encrypted_record_events SET record_id='ghost', position=1 "
                    "WHERE batch_id=? AND record_id='b'", (batch_id,))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))
        self.tamper("UPDATE encrypted_record_events SET tenant='intruder' "
                    "WHERE batch_id=? AND record_id='ghost'", (batch_id,))
        self.assertEqual(self.read_by_ids(["a", "b"]),
                         (422, {"error": "integrity_error"}))

    def test_record_linked_to_other_batch_is_integrity_error(self):
        original_batch = self.ingest([sealed_record("a")])[1]["batch_id"]
        # Repoint the record at a well-formed but nonexistent batch id: the
        # involved batch lookup finds nothing and the review fails with 422.
        self.tamper("UPDATE encrypted_records SET batch_id='batch_%s' "
                    "WHERE id='a'" % ("0" * 32))
        self.assertEqual(self.read_by_ids(["a"]),
                         (422, {"error": "integrity_error"}))
        # The original batch (its record now gone) is itself inconsistent.
        self.assertEqual(self.get_batch(original_batch)[0], 422)

    def test_corrupt_unrequested_record_field_shapes_are_integrity_error(self):
        self.ingest([sealed_record("a"), sealed_record("b")])
        cases = [
            ("algorithm", "AES-256-CBC"),
            ("envelope_nonce", b"short"),
            ("wrapped_key", b"x" * 12),
            ("tag", b"x" * 15),
            ("encryption_key_id", "k" * 129),
        ]
        for column, value in cases:
            self.tamper(f"UPDATE encrypted_records SET {column}=? WHERE id='b'",
                        (value,))
            with self.subTest(column=column):
                self.assertEqual(self.read_by_ids(["a"]),
                                 (422, {"error": "integrity_error"}))
            good = {"algorithm": "AES-256-GCM", "envelope_nonce": b"\x00" * 12,
                    "wrapped_key": b"\x00" * 48, "tag": b"\x00" * 16,
                    "encryption_key_id": "client-key-1"}[column]
            self.tamper(f"UPDATE encrypted_records SET {column}=? WHERE id='b'",
                        (good,))
        self.assertEqual(self.read_by_ids(["a", "b"])[0], 200)

    def test_corruption_in_unrelated_batch_does_not_affect_result(self):
        good_batch = self.ingest([sealed_record("a"), sealed_record("b")])[1]["batch_id"]
        other_batch = self.ingest([sealed_record("x"), sealed_record("y")])[1]["batch_id"]
        # Damage the other batch in several ways; none of its ids are requested.
        self.tamper("DELETE FROM encrypted_record_events WHERE batch_id=?",
                    (other_batch,))
        self.tamper("UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
                    (other_batch,))
        status, body = self.read_by_ids(["b", "a"])
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]],
                         [good_batch, good_batch])
        # And the damaged batch still fails when its own id is requested.
        self.assertEqual(self.read_by_ids(["x"]),
                         (422, {"error": "integrity_error"}))

    def test_equal_length_ciphertext_change_is_returned_verbatim(self):
        record = sealed_record("a")
        self.ingest([record])
        original = base64.b64decode(record["ciphertext"]["data"])
        flipped = bytearray(original)
        flipped[0] ^= 0xFF
        self.tamper("UPDATE encrypted_records SET ciphertext=? WHERE id='a'",
                    (bytes(flipped),))
        status, body = self.read_by_ids(["a"])
        self.assertEqual(status, 200)
        self.assertEqual(body["items"][0]["ciphertext"]["data"], b64(bytes(flipped)))

    # -- storage failure ---------------------------------------------------

    def test_storage_failure_on_existence_query_is_503(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_records")
        raw.close()
        for ids in (["a"], ["ghost"]):
            with self.subTest(ids=ids):
                self.assertEqual(self.read_by_ids(ids),
                                 (503, {"error": "storage_error"}))

    def test_storage_failure_after_existence_is_503(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.read_by_ids(["a"]),
                         (503, {"error": "storage_error"}))

        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TABLE encrypted_batches ("
                "batch_id TEXT NOT NULL PRIMARY KEY, tenant TEXT NOT NULL, "
                "record_count INTEGER NOT NULL, created_at TEXT NOT NULL)"
            )
        raw.close()
        # Existence still passes (encrypted_records intact) but events fail.
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_record_events")
        raw.close()
        self.assertEqual(self.read_by_ids(["a"]),
                         (503, {"error": "storage_error"}))

    def test_service_recovers_after_storage_failure(self):
        self.ingest([sealed_record("a")])
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.read_by_ids(["a"])[0], 503)
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TABLE encrypted_batches ("
                "batch_id TEXT NOT NULL PRIMARY KEY, tenant TEXT NOT NULL, "
                "record_count INTEGER NOT NULL, created_at TEXT NOT NULL)"
            )
            raw.execute(
                "INSERT INTO encrypted_batches "
                "(batch_id, tenant, record_count, created_at) "
                "SELECT batch_id, tenant, COUNT(*), '2026-01-01T00:00:00+00:00' "
                "FROM encrypted_records GROUP BY batch_id"
            )
        raw.close()
        # Storage is healthy again: the surviving record and its event make a
        # consistent batch, and brand new batches ingest and read normally.
        self.assertEqual(self.read_by_ids(["a"])[0], 200)
        status, body = self.ingest([sealed_record("later")])
        self.assertEqual(status, 201)
        self.assertEqual(self.read_by_ids(["later"])[0], 200)

    # -- concurrency -------------------------------------------------------

    def test_concurrent_access_observes_only_complete_serial_states(self):
        seeded = [sealed_record(f"s{i}") for i in range(4)]
        self.ingest(seeded[:2])
        self.ingest(seeded[2:])
        stable_ids = [record["id"] for record in seeded]
        stable = {
            item["id"]: item
            for item in self.read_by_ids(stable_ids)[1]["items"]
        }

        barrier = threading.Barrier(7)
        failures = []
        lock = threading.Lock()

        def reader():
            barrier.wait()
            for _ in range(60):
                status, body = self.read_by_ids(stable_ids)
                if status != 200:
                    with lock:
                        failures.append(("stable", status, body))
                    continue
                if body["count"] != 4:
                    with lock:
                        failures.append(("count", body["count"]))
                    continue
                for item in body["items"]:
                    original = stable[item["id"]]
                    if (item["ciphertext"] != original["ciphertext"]
                            or item["batch_id"] != original["batch_id"]):
                        with lock:
                            failures.append(("drift", item["id"]))

        def writer(index):
            barrier.wait()
            for _ in range(5):
                records = [sealed_record(f"w{index}_{os.urandom(4).hex()}{i}")
                           for i in range(2)]
                result = self.ingest(records)
                if result[0] != 201:
                    with lock:
                        failures.append(("write", result))
                    continue
                ids = [record["id"] for record in records]
                status, body = self.read_by_ids(ids)
                if status != 200 or [i["id"] for i in body["items"]] != ids:
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
        # Sealed records do not participate in rotation and stay fully readable.
        status, body = self.read_by_ids(stable_ids)
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], stable_ids)

    # -- existing endpoints unchanged --------------------------------------

    def test_other_endpoints_keep_working_alongside(self):
        status, _ = self.ingest([sealed_record("e1")])
        self.assertEqual(status, 201)
        self.assertEqual(
            self.request("POST", "/v1/records",
                         {"id": "p1", "plaintext": "原文"}),
            (201, {"id": "p1", "key_version": 1}),
        )
        self.assertEqual(self.request("POST", "/v1/records/batch/read",
                                      {"ids": ["p1"]})[0], 200)
        self.assertEqual(self.request("GET", "/v1/encrypted-records/batches")[0], 200)
        self.assertEqual(self.request("GET", "/health", None, None)[0], 200)


if __name__ == "__main__":
    unittest.main()
