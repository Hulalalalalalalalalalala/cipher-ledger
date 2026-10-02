"""Contract tests for the idempotency-key write receipt.

``GET /v1/encrypted-records/receipts/{key}`` lets a client confirm a sealed
batch write by its ``Idempotency-Key`` without resubmitting ciphertext. These
tests cover the receipt body, tenant-first error precedence, key grammar,
query-string ignoring, tenant isolation, 404 for unbound keys and keyless
legacy batches, the 422 integrity cases (missing/foreign/illegal bound batch,
binding timestamp drift, whole-batch review), 503 on every SQLite read
failure, read-only behavior, atomicity versus a rolled-back commit, restart
and key-rotation stability, and serialization against concurrent writes.
"""

import base64
import copy
import json
import os
import socket
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
RECEIPT_PATH = "/v1/encrypted-records/receipts/"
IDEMPOTENCY_TABLE = "encrypted_batch_idempotency_keys"
RECEIPT_FIELDS = {"batch_id", "count", "results", "created_at"}
RESULT_FIELDS = {"id", "status"}


def b64(raw: bytes) -> str:
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


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    # -- transport helpers -------------------------------------------------

    def get_receipt(self, key, tenant="acme", suffix=""):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        request = urllib.request.Request(
            self.harness.base + RECEIPT_PATH + key + suffix,
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def raw_get(self, target, tenant=("acme",)):
        """Send a raw GET; ``tenant`` tuple carries the raw header or None."""
        header_lines = []
        if tenant and tenant[0] is not None:
            header_lines.append(f"X-Tenant-ID: {tenant[0]}")
        request_lines = [
            f"GET {target} HTTP/1.1",
            f"Host: {self.harness.host}",
            "Connection: close",
            *header_lines,
            "",
            "",
        ]
        raw = "\r\n".join(request_lines).encode("ascii")
        with socket.create_connection((self.harness.host, self.harness.port)) as sock:
            sock.sendall(raw)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        head, _, body = response.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n", 1)[0].split()[1])
        return status, json.loads(body)

    def ingest(self, records, key=None, tenant="acme"):
        headers = {"Content-Type": "application/json"}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
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

    def rotate(self, version):
        request = urllib.request.Request(
            self.harness.base + "/v1/keys/rotate",
            data=json.dumps({"version": version}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    # -- success body ------------------------------------------------------

    def test_receipt_matches_first_write_plus_batch_timestamp(self):
        records = [sealed_record("zeta"), sealed_record("alpha"), sealed_record("mid")]
        first_status, first = self.ingest(copy.deepcopy(records), key="order-1")
        self.assertEqual(first_status, 201)

        status, receipt = self.get_receipt("order-1")
        self.assertEqual(status, 200)
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(receipt["batch_id"], first["batch_id"])
        self.assertEqual(receipt["count"], first["count"])
        self.assertEqual(receipt["results"], first["results"])
        self.assertEqual(
            receipt["results"],
            [
                {"id": "zeta", "status": "created"},
                {"id": "alpha", "status": "created"},
                {"id": "mid", "status": "created"},
            ],
        )
        for result in receipt["results"]:
            self.assertEqual(set(result), RESULT_FIELDS)
        # created_at comes verbatim from the batch row.
        raw = self.db()
        try:
            batch_created_at = raw.execute(
                "SELECT created_at FROM encrypted_batches WHERE batch_id=?",
                (first["batch_id"],),
            ).fetchone()[0]
            binding_created_at = raw.execute(
                f"SELECT created_at FROM {IDEMPOTENCY_TABLE} "
                "WHERE tenant=? AND idempotency_key=?",
                ("acme", "order-1"),
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(receipt["created_at"], batch_created_at)
        self.assertEqual(receipt["created_at"], binding_created_at)

    def test_receipt_contains_no_ciphertext_envelope_or_key_material(self):
        record = sealed_record("a")
        secret_tokens = [
            record["envelope"]["nonce"],
            record["envelope"]["wrapped_key"],
            record["ciphertext"]["data"],
            record["ciphertext"]["nonce"],
            record["ciphertext"]["tag"],
            record["key_id"],
        ]
        self.assertEqual(self.ingest([record], key="k-1")[0], 201)
        status, receipt = self.get_receipt("k-1")
        self.assertEqual(status, 200)
        serialized = json.dumps(receipt)
        for token in secret_tokens:
            self.assertNotIn(token, serialized)
        for absent in ("ciphertext", "envelope", "wrapped_key", "nonce", "algorithm", "metadata"):
            self.assertNotIn(absent, serialized)

    def test_single_and_boundary_length_keys(self):
        self.assertEqual(self.ingest([sealed_record("a")], key="a")[0], 201)
        self.assertEqual(self.get_receipt("a")[0], 200)
        long_key = "k" * 64
        self.assertEqual(self.ingest([sealed_record("b")], key=long_key)[0], 201)
        self.assertEqual(self.get_receipt(long_key)[0], 200)

    def test_query_parameters_are_ignored(self):
        self.ingest([sealed_record("a")], key="k-1")
        for suffix in (
            "?anything=whatever",
            "?limit=abc&cursor=%21&",
            "?foo",
            "?x=1&y=2&z=3",
        ):
            with self.subTest(suffix=suffix):
                status, body = self.get_receipt("k-1", suffix=suffix)
                self.assertEqual(status, 200)
                self.assertEqual(set(body), RECEIPT_FIELDS)

    def test_repeated_reads_are_identical_and_write_nothing(self):
        self.ingest([sealed_record("a"), sealed_record("b")], key="k-1")
        seen = []
        for _ in range(3):
            status, receipt = self.get_receipt("k-1")
            self.assertEqual(status, 200)
            seen.append(receipt)
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[1], seen[2])
        raw = self.db()
        try:
            counts = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE}").fetchone()[0],
            )
        finally:
            raw.close()
        self.assertEqual(counts, (1, 2, 2, 1))

    # -- error precedence: 403 then 400 ------------------------------------

    def test_missing_or_invalid_tenant_is_403_even_for_empty_or_bad_key(self):
        # Targets use only wire-legal request targets; tenant authorization is
        # settled before the path segment is grammar-checked at all.
        targets = (RECEIPT_PATH, RECEIPT_PATH + "good-key", RECEIPT_PATH + "bad-key!",
                   RECEIPT_PATH + "a%20b")
        for tenant in (None, "bad-tenant!", "x" * 65):
            for target in targets:
                with self.subTest(tenant=tenant, target=target):
                    status, body = self.raw_get(target, tenant=(tenant,))
                    self.assertEqual(status, 403)
                    self.assertEqual(body, {"error": "TENANT_RECORD_FORBIDDEN"})

    def test_403_precedence_does_not_require_binding_to_exist(self):
        # A validly-shaped key that is also unbound is irrelevant: tenant wins.
        status, body = self.get_receipt("unbound", tenant=None)
        self.assertEqual((status, body), (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_valid_tenant_but_empty_or_malformed_key_is_400(self):
        bad_targets = (
            RECEIPT_PATH,  # no segment at all
            RECEIPT_PATH + "a.b",
            RECEIPT_PATH + "a/b",
            RECEIPT_PATH + "a:b",
            RECEIPT_PATH + "a%20b",
            RECEIPT_PATH + "x" * 65,
        )
        for target in bad_targets:
            with self.subTest(target=target):
                status, body = self.raw_get(target)
                self.assertEqual(status, 400)
                self.assertEqual(body, {"error": "invalid_request"})

    def test_400_shape_check_runs_before_binding_lookup(self):
        # Malformed key returns 400 regardless of whether "something" is bound.
        self.ingest([sealed_record("a")], key="k-1")
        self.assertEqual(
            self.raw_get(RECEIPT_PATH + "k.1"),
            (400, {"error": "invalid_request"}),
        )

    # -- 404: unbound / isolated / legacy ----------------------------------

    def test_unbound_key_is_404(self):
        self.assertEqual(
            self.get_receipt("never-used"),
            (404, {"error": "not_found"}),
        )

    def test_keyless_legacy_batch_creates_no_receipt(self):
        status, body = self.ingest([sealed_record("legacy")])
        self.assertEqual(status, 201)
        # No key was ever supplied, so no binding exists for any key name.
        for guessed in ("legacy", "batch", body["batch_id"]):
            with self.subTest(guessed=guessed):
                self.assertEqual(self.get_receipt(guessed), (404, {"error": "not_found"}))
        raw = self.db()
        try:
            count = raw.execute(f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE}").fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(count, 0)

    def test_key_value_is_case_sensitive_and_tenant_isolated(self):
        records = [sealed_record("shared")]
        first_a, _ = self.ingest(copy.deepcopy(records), key="Same-Key", tenant="alpha")
        first_b, _ = self.ingest(copy.deepcopy(records), key="Same-Key", tenant="beta")
        self.assertEqual(first_a, 201)
        self.assertEqual(first_b, 201)
        # Different case is a different key: unbound for every tenant.
        self.assertEqual(self.get_receipt("same-key", tenant="alpha"), (404, {"error": "not_found"}))
        self.assertEqual(self.get_receipt("same-key", tenant="beta"), (404, {"error": "not_found"}))
        # Same name for a third tenant is unbound even though both others bind it.
        self.assertEqual(self.get_receipt("Same-Key", tenant="gamma"), (404, {"error": "not_found"}))
        # Each tenant reads only its own receipt.
        status_a, receipt_a = self.get_receipt("Same-Key", tenant="alpha")
        status_b, receipt_b = self.get_receipt("Same-Key", tenant="beta")
        self.assertEqual(status_a, 200)
        self.assertEqual(status_b, 200)
        self.assertNotEqual(receipt_a["batch_id"], receipt_b["batch_id"])

    # -- idempotent replay / restart / rotation ----------------------------

    def test_idempotent_replay_does_not_change_receipt(self):
        records = [sealed_record("a"), sealed_record("b")]
        _, first = self.ingest(copy.deepcopy(records), key="k-1")
        for _ in range(2):
            status, replay = self.ingest(copy.deepcopy(records), key="k-1")
            self.assertEqual(status, 200)
            self.assertEqual(replay, first)
        _, receipt = self.get_receipt("k-1")
        self.assertEqual(receipt["batch_id"], first["batch_id"])
        self.assertEqual(receipt["count"], first["count"])
        self.assertEqual(receipt["results"], first["results"])

    def test_receipt_survives_restart(self):
        records = [sealed_record("a"), sealed_record("b"), sealed_record("c")]
        _, first = self.ingest(copy.deepcopy(records), key="persist-1")
        before_status, before = self.get_receipt("persist-1")
        self.assertEqual(before_status, 200)

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        after_status, after = self.get_receipt("persist-1")
        self.assertEqual(after_status, 200)
        self.assertEqual(after, before)
        self.assertEqual(after["results"], first["results"])

    def test_receipt_is_unchanged_by_key_rotation(self):
        # Sealed batches do not participate in server-side key rotation; the
        # receipt (like the batch tables) is byte-for-byte the same afterwards.
        self.ingest([sealed_record("a")], key="k-1")
        _, before = self.get_receipt("k-1")
        status, body = self.rotate(2)
        self.assertEqual(status, 200)
        self.assertEqual(body["active_version"], 2)
        _, after = self.get_receipt("k-1")
        self.assertEqual(after, before)

    # -- read-only: unrelated corruption -----------------------------------

    def test_damage_to_an_unrelated_unbound_batch_does_not_affect_receipt(self):
        _, bound = self.ingest([sealed_record("a")], key="k-1")
        # A second, keyless batch that the receipt's key does not reference.
        _, other = self.ingest([sealed_record("b")])
        self.assertNotEqual(bound["batch_id"], other["batch_id"])
        raw = self.db()
        with raw:
            # Corrupt the unrelated batch: remove its append event.
            raw.execute(
                "DELETE FROM encrypted_record_events WHERE batch_id=?",
                (other["batch_id"],),
            )
        raw.close()
        status, receipt = self.get_receipt("k-1")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["batch_id"], bound["batch_id"])
        self.assertEqual(receipt["results"], [{"id": "a", "status": "created"}])

    def test_read_repairs_nothing(self):
        _, first = self.ingest([sealed_record("a")], key="k-1")
        self.assertEqual(self.get_receipt("k-1")[0], 200)
        raw = self.db()
        try:
            rows = {
                "binding": raw.execute(
                    f"SELECT tenant, idempotency_key, batch_id, created_at "
                    f"FROM {IDEMPOTENCY_TABLE} WHERE tenant='acme' AND idempotency_key='k-1'"
                ).fetchone(),
                "batch": raw.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id=?",
                    (first["batch_id"],),
                ).fetchone(),
            }
        finally:
            raw.close()
        self.assertEqual(tuple(rows["binding"]), ("acme", "k-1", first["batch_id"], rows["batch"]["created_at"]))

    # -- 422: bound batch integrity -----------------------------------------

    def test_bound_batch_missing_is_integrity_error(self):
        _, body = self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DELETE FROM encrypted_batches WHERE batch_id=?", (body["batch_id"],))
        raw.close()
        self.assertEqual(
            self.get_receipt("k-1"),
            (422, {"error": "integrity_error"}),
        )

    def test_bound_batch_repointed_at_another_tenant_is_integrity_error(self):
        _, alpha = self.ingest([sealed_record("a")], key="k-1", tenant="alpha")
        _, beta = self.ingest([sealed_record("a")], key="k-1", tenant="beta")
        raw = self.db()
        with raw:
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                "WHERE tenant='alpha' AND idempotency_key='k-1'",
                (beta["batch_id"],),
            )
        raw.close()
        # Alpha's binding now points at beta's batch: relationship failure.
        self.assertEqual(
            self.get_receipt("k-1", tenant="alpha"),
            (422, {"error": "integrity_error"}),
        )
        # Beta owns that batch but has no binding row under alpha's tenant;
        # beta's own same-named binding is untouched and still serves.
        status, receipt = self.get_receipt("k-1", tenant="beta")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["batch_id"], beta["batch_id"])

    def test_illegal_bound_batch_id_is_integrity_error(self):
        _, body = self.ingest([sealed_record("a")], key="k-1")
        for bad in ("not-a-batch", "batch_" + "z" * 32, "batch_1234"):
            with self.subTest(bad=bad):
                raw = self.db()
                with raw:
                    raw.execute(
                        f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                        "WHERE tenant='acme' AND idempotency_key='k-1'",
                        (bad,),
                    )
                raw.close()
                self.assertEqual(
                    self.get_receipt("k-1"),
                    (422, {"error": "integrity_error"}),
                )
                # Restore so the next sub-case starts from a valid binding.
                raw = self.db()
                with raw:
                    raw.execute(
                        f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                        "WHERE tenant='acme' AND idempotency_key='k-1'",
                        (body["batch_id"],),
                    )
                raw.close()

    def test_binding_timestamp_not_string_or_drifting_is_integrity_error(self):
        _, body = self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            # A BLOB survives the column's TEXT affinity and reads back as bytes.
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET created_at=CAST('x' AS BLOB) "
                "WHERE tenant='acme' AND idempotency_key='k-1'"
            )
        raw.close()
        self.assertEqual(self.get_receipt("k-1"), (422, {"error": "integrity_error"}))

        raw = self.db()
        with raw:
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET created_at='2000-01-01T00:00:00+00:00' "
                "WHERE tenant='acme' AND idempotency_key='k-1'"
            )
        raw.close()
        # A string that no longer equals the batch row's value is drift too.
        self.assertEqual(self.get_receipt("k-1"), (422, {"error": "integrity_error"}))

    def test_whole_batch_review_failures_are_integrity_errors(self):
        _, body = self.ingest([sealed_record("a"), sealed_record("b")], key="k-1")

        def mutate(sql, value):
            raw = self.db()
            with raw:
                raw.execute(sql, value)
            raw.close()

        cases = [
            ("count mismatch",
             "UPDATE encrypted_batches SET record_count=1 WHERE batch_id=?",
             (body["batch_id"],)),
            ("missing event",
             "DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
             (body["batch_id"],)),
            ("unsupported algorithm",
             "UPDATE encrypted_records SET algorithm='BOGUS' WHERE batch_id=? AND position=0",
             (body["batch_id"],)),
            ("cross-tenant record",
             "UPDATE encrypted_records SET tenant='other' WHERE batch_id=? AND position=0",
             (body["batch_id"],)),
            ("corrupt metadata",
             "UPDATE encrypted_records SET metadata='{not json' WHERE batch_id=? AND position=0",
             (body["batch_id"],)),
        ]
        for label, sql, value in cases:
            with self.subTest(label=label):
                mutate(sql, value)
                self.assertEqual(
                    self.get_receipt("k-1"),
                    (422, {"error": "integrity_error"}),
                )

    # -- 503: every SQLite read failure ------------------------------------

    def test_binding_lookup_sqlite_failure_is_storage_error(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute(f"DROP TABLE {IDEMPOTENCY_TABLE}")
        raw.close()
        self.assertEqual(
            self.get_receipt("k-1"),
            (503, {"error": "storage_error"}),
        )

    def test_batch_read_sqlite_failure_is_storage_error_not_integrity(self):
        _, body = self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        # Binding lookup succeeds; the missing *table* is a read failure,
        # distinct from a successful read returning no batch row (422).
        self.assertEqual(self.get_receipt("k-1"), (503, {"error": "storage_error"}))

    def test_record_read_sqlite_failure_is_storage_error(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_records")
        raw.close()
        self.assertEqual(self.get_receipt("k-1"), (503, {"error": "storage_error"}))

    def test_event_read_sqlite_failure_is_storage_error(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_record_events")
        raw.close()
        self.assertEqual(self.get_receipt("k-1"), (503, {"error": "storage_error"}))

    # -- atomicity / concurrency -------------------------------------------

    def test_failed_commit_leaves_receipt_unbound(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END"
            )
        raw.close()
        status, body = self.ingest([sealed_record("a"), sealed_record("b")], key="k-rollback")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        # No partial commit: the key is still unbound and reads as 404.
        self.assertEqual(
            self.get_receipt("k-rollback"),
            (404, {"error": "not_found"}),
        )

    def test_concurrent_readers_see_only_404_or_complete_receipt(self):
        records = [sealed_record(f"r{i}") for i in range(4)]
        barrier = threading.Barrier(9)
        outcomes = []
        lock = threading.Lock()

        def write():
            barrier.wait()
            with lock:
                outcomes.append(("write",) + self.ingest(copy.deepcopy(records), key="hot-key"))

        def read():
            barrier.wait()
            with lock:
                outcomes.append(("read",) + self.get_receipt("hot-key"))

        threads = [threading.Thread(target=write)]
        threads += [threading.Thread(target=read) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        write_results = [o for o in outcomes if o[0] == "write"]
        read_results = [o for o in outcomes if o[0] == "read"]
        self.assertEqual(len(write_results), 1)
        self.assertEqual(write_results[0][1], 201)
        expected_results = [
            {"id": f"r{i}", "status": "created"} for i in range(4)
        ]
        saw_unbound = False
        saw_complete = False
        for _, status, body in read_results:
            self.assertIn(status, (404, 200))
            if status == 404:
                saw_unbound = True
                self.assertEqual(body, {"error": "not_found"})
            else:
                saw_complete = True
                self.assertEqual(set(body), RECEIPT_FIELDS)
                self.assertEqual(body["count"], 4)
                self.assertEqual(body["results"], expected_results)
                self.assertEqual(body["batch_id"], write_results[0][2]["batch_id"])
        # Under the barrier the readers race the one writer; the contract is
        # the disjunction above (at least one side is always observable).
        self.assertTrue(saw_unbound or saw_complete)

        # Final state after all threads settle: the complete receipt.
        status, receipt = self.get_receipt("hot-key")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["results"], expected_results)

    def test_concurrent_same_key_commits_then_single_consistent_receipt(self):
        records = [sealed_record("r0")]
        barrier = threading.Barrier(8)
        statuses = []

        def submit():
            barrier.wait()
            status, _ = self.ingest(copy.deepcopy(records), key="hot-key-2")
            statuses.append(status)

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        status, receipt = self.get_receipt("hot-key-2")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["count"], 1)
        self.assertEqual(receipt["results"], [{"id": "r0", "status": "created"}])
        raw = self.db()
        try:
            count = raw.execute(
                f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE} "
                "WHERE tenant='acme' AND idempotency_key='hot-key-2'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
