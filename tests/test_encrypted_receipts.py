"""Contract tests for GET /v1/encrypted-records/receipts/{key}.

The endpoint returns the commit receipt bound to an Idempotency-Key without
re-transmitting ciphertext. These tests cover the success shape (matching the
first write's 201 body plus the batch's created_at), tenant/key error
precedence, tenant isolation, the integrity review of the binding and its
associated batch (422), storage failures (503), read-only behaviour, replay
stability, restart/rotation persistence and serial visibility under
concurrency. Most tampering is performed directly on the SQLite file.
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
RECEIPT_PREFIX = "/v1/encrypted-records/receipts/"
IDEMPOTENCY_TABLE = "encrypted_batch_idempotency_keys"


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

    def receipt(self, key, tenant="acme", suffix=""):
        return self.raw_get(RECEIPT_PREFIX + key + suffix, tenant=tenant)

    def raw_get(self, path, tenant="acme"):
        """GET an arbitrary raw path (spaces/punctuation are sent verbatim)."""
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self.harness.host}",
            "Connection: close",
        ]
        if tenant is not None:
            request_lines.append(f"X-Tenant-ID: {tenant}")
        raw = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")
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

    def get(self, path, tenant="acme"):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        request = urllib.request.Request(self.harness.base + path, headers=headers)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    # -- success shape ------------------------------------------------------

    def test_receipt_matches_first_write_response_plus_created_at(self):
        records = [sealed_record("zeta"), sealed_record("alpha"), sealed_record("mid")]
        status, created = self.ingest(copy.deepcopy(records), key="order-1")
        self.assertEqual(status, 201)
        status, receipt = self.receipt("order-1")
        self.assertEqual(status, 200)
        # batch_id/count/results are exactly the first success's body.
        self.assertEqual(receipt["batch_id"], created["batch_id"])
        self.assertEqual(receipt["count"], created["count"])
        self.assertEqual(receipt["results"], created["results"])
        self.assertEqual(
            [item["id"] for item in receipt["results"]], ["zeta", "alpha", "mid"]
        )
        self.assertTrue(all(item["status"] == "created" for item in receipt["results"]))
        # created_at is the batch row's verbatim string.
        _, batch = self.raw_get(
            f"/v1/encrypted-records/batches/{created['batch_id']}"
        )
        self.assertEqual(receipt["created_at"], batch["created_at"])
        # The receipt carries no ciphertext, envelope or key material.
        self.assertEqual(
            set(receipt), {"batch_id", "count", "results", "created_at"}
        )
        self.assertEqual(set(receipt["results"][0]), {"id", "status"})

    def test_existing_binding_needs_no_rewrite(self):
        # A binding committed by an earlier request is queryable directly.
        records = [sealed_record("a")]
        _, created = self.ingest(copy.deepcopy(records), key="k-old")
        status, receipt = self.receipt("k-old")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["batch_id"], created["batch_id"])

    def test_query_parameters_are_ignored(self):
        self.ingest([sealed_record("a")], key="k-1")
        status, receipt = self.receipt("k-1", suffix="?limit=1&cursor=bogus&x=y")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["count"], 1)

    def test_key_format_boundaries_accepted(self):
        self.ingest([sealed_record("a")], key="k")
        self.assertEqual(self.receipt("k")[0], 200)
        long_key = "K" * 64
        self.ingest([sealed_record("b")], key=long_key)
        self.assertEqual(self.receipt(long_key)[0], 200)

    def test_key_value_is_case_sensitive(self):
        self.ingest([sealed_record("a")], key="Order-1")
        self.assertEqual(self.receipt("order-1"), (404, {"error": "not_found"}))
        self.assertEqual(self.receipt("Order-1")[0], 200)

    # -- tenant and key validation precedence --------------------------------

    def test_missing_or_invalid_tenant_is_403_and_precedes_key_format(self):
        self.ingest([sealed_record("a")], key="k-1")
        for tenant in (None, "bad tenant!"):
            for key in ("k-1", "bad!key", "", "x" * 65):
                with self.subTest(tenant=tenant, key=key):
                    status, body = self.receipt(key, tenant=tenant)
                    self.assertEqual((status, body), (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_empty_and_malformed_keys_are_400(self):
        self.ingest([sealed_record("a")], key="k-1")
        # A space can never reach the router (it breaks the request line
        # itself); these invalid keys all arrive as a well-formed target.
        for key in ("", "bad!key", "a.b", "a/b", "a:b", "%20", "x" * 65):
            with self.subTest(key=key):
                status, body = self.receipt(key)
                self.assertEqual((status, body), (400, {"error": "invalid_request"}))

    # -- not found ------------------------------------------------------------

    def test_unbound_key_is_404(self):
        self.assertEqual(self.receipt("never-used"), (404, {"error": "not_found"}))

    def test_key_bound_only_by_another_tenant_is_404(self):
        self.ingest([sealed_record("a")], key="shared", tenant="alpha")
        self.assertEqual(
            self.receipt("shared", tenant="beta"), (404, {"error": "not_found"})
        )
        # Alpha's own receipt is unaffected.
        self.assertEqual(self.receipt("shared", tenant="alpha")[0], 200)

    def test_keyless_batch_produces_no_receipt(self):
        _, created = self.ingest([sealed_record("legacy")])
        self.assertEqual(created["count"], 1)
        raw = self.db()
        try:
            bound = raw.execute(
                f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE} WHERE batch_id=?",
                (created["batch_id"],),
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(bound, 0)
        self.assertEqual(self.receipt("legacy"), (404, {"error": "not_found"}))

    # -- integrity failures: 422 ---------------------------------------------

    def test_missing_associated_batch_is_422(self):
        _, created = self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute(
                "DELETE FROM encrypted_batches WHERE batch_id=?",
                (created["batch_id"],),
            )
        raw.close()
        self.assertEqual(self.receipt("k-1"), (422, {"error": "integrity_error"}))

    def test_binding_repointed_at_other_tenants_batch_is_422(self):
        _, alpha = self.ingest([sealed_record("a")], key="k-1", tenant="alpha")
        _, beta = self.ingest([sealed_record("b")], key="k-1", tenant="beta")
        raw = self.db()
        with raw:
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                "WHERE tenant='alpha' AND idempotency_key='k-1'",
                (beta["batch_id"],),
            )
        raw.close()
        self.assertEqual(
            self.receipt("k-1", tenant="alpha"), (422, {"error": "integrity_error"})
        )
        # Beta's own receipt remains intact.
        self.assertEqual(self.receipt("k-1", tenant="beta")[0], 200)
        self.assertTrue(alpha["batch_id"])

    def test_malformed_bound_batch_id_is_422(self):
        self.ingest([sealed_record("a")], key="k-1")
        for bad in ("bogus", "batch_" + "0" * 31, "batch_" + "G" * 32, ""):
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
                    self.receipt("k-1"), (422, {"error": "integrity_error"})
                )

    def test_non_string_binding_timestamp_is_422(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            # TEXT affinity keeps a BLOB as a BLOB, so this stores a
            # non-string created_at on the binding.
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET created_at=x'07' "
                "WHERE tenant='acme' AND idempotency_key='k-1'"
            )
        raw.close()
        self.assertEqual(self.receipt("k-1"), (422, {"error": "integrity_error"}))

    def test_binding_timestamp_differing_from_batch_is_422(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET created_at='1999-01-01T00:00:00+00:00' "
                "WHERE tenant='acme' AND idempotency_key='k-1'"
            )
        raw.close()
        self.assertEqual(self.receipt("k-1"), (422, {"error": "integrity_error"}))

    def test_batch_consistency_drift_is_422(self):
        # Each tampering gets its own key/batch in the same database.
        tamperings = [
            "UPDATE encrypted_batches SET record_count=1 WHERE batch_id=?",
            "DELETE FROM encrypted_record_events WHERE batch_id=? AND position=1",
            "UPDATE encrypted_records SET tenant='other' "
            "WHERE batch_id=? AND position=0",
            "UPDATE encrypted_records SET algorithm='AES-192-GCM' "
            "WHERE batch_id=? AND position=0",
        ]
        for index, statement in enumerate(tamperings):
            with self.subTest(tampering=statement):
                key = f"k-drift-{index}"
                _, created = self.ingest(
                    [sealed_record(f"a{index}"), sealed_record(f"b{index}")], key=key
                )
                raw = self.db()
                with raw:
                    raw.execute(statement, (created["batch_id"],))
                raw.close()
                self.assertEqual(
                    self.receipt(key), (422, {"error": "integrity_error"})
                )

    def test_corruption_in_unassociated_batch_does_not_affect_receipt(self):
        _, wanted = self.ingest([sealed_record("a")], key="k-1")
        _, other = self.ingest([sealed_record("b")], key="k-2")
        raw = self.db()
        with raw:
            raw.execute(
                "UPDATE encrypted_batches SET record_count=99 WHERE batch_id=?",
                (other["batch_id"],),
            )
        raw.close()
        status, receipt = self.receipt("k-1")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["batch_id"], wanted["batch_id"])
        # The corrupted batch itself still fails its own receipt.
        self.assertEqual(self.receipt("k-2"), (422, {"error": "integrity_error"}))

    # -- storage failures: 503 ------------------------------------------------

    def test_binding_lookup_sqlite_failure_is_503(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute(f"DROP TABLE {IDEMPOTENCY_TABLE}")
        raw.close()
        self.assertEqual(self.receipt("k-1"), (503, {"error": "storage_error"}))

    def test_batch_read_sqlite_failure_is_503(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.receipt("k-1"), (503, {"error": "storage_error"}))

    def test_record_read_sqlite_failure_is_503(self):
        self.ingest([sealed_record("a")], key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_records")
        raw.close()
        self.assertEqual(self.receipt("k-1"), (503, {"error": "storage_error"}))

    # -- error bodies carry no partial receipt --------------------------------

    def test_error_bodies_contain_only_the_error_field(self):
        self.ingest([sealed_record("a")], key="k-1")
        for key, tenant in (
            ("k-1", None),
            ("bad!key", "acme"),
            ("unbound", "acme"),
        ):
            with self.subTest(key=key, tenant=tenant):
                _, body = self.receipt(key, tenant=tenant)
                self.assertEqual(set(body), {"error"})
        raw = self.db()
        with raw:
            raw.execute(
                "DELETE FROM encrypted_batches WHERE batch_id IN "
                f"(SELECT batch_id FROM {IDEMPOTENCY_TABLE})"
            )
        raw.close()
        _, body = self.receipt("k-1")
        self.assertEqual(body, {"error": "integrity_error"})

    # -- read-only, replay and rollback semantics ------------------------------

    def test_query_does_not_modify_storage(self):
        records = [sealed_record("a"), sealed_record("b")]
        self.ingest(copy.deepcopy(records), key="k-1")
        before = self._dump_tables()
        self.assertEqual(self.receipt("k-1")[0], 200)
        self.assertEqual(self.receipt("k-1")[0], 200)
        self.assertEqual(self._dump_tables(), before)

    def test_replay_does_not_change_receipt(self):
        records = [sealed_record("a")]
        self.ingest(copy.deepcopy(records), key="k-1")
        _, first_receipt = self.receipt("k-1")
        # Idempotent replay of the same content returns 200 and writes nothing.
        self.assertEqual(self.ingest(copy.deepcopy(records), key="k-1")[0], 200)
        self.assertEqual(self.receipt("k-1"), (200, first_receipt))

    def test_rolled_back_commit_leaves_key_unbound(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END"
            )
        raw.close()
        status, body = self.ingest([sealed_record("a")], key="k-1")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        self.assertEqual(self.receipt("k-1"), (404, {"error": "not_found"}))
        # Recovery: drop the trigger, commit, and the receipt appears whole.
        raw = self.db()
        with raw:
            raw.execute("DROP TRIGGER block_encrypted_insert")
        raw.close()
        _, created = self.ingest([sealed_record("a")], key="k-1")
        status, receipt = self.receipt("k-1")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["batch_id"], created["batch_id"])

    # -- persistence across restart and rotation -------------------------------

    def test_receipt_survives_restart(self):
        records = [sealed_record("a"), sealed_record("b")]
        self.ingest(copy.deepcopy(records), key="persist-1")
        _, before = self.receipt("persist-1")

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        self.assertEqual(self.receipt("persist-1"), (200, before))

    def test_receipt_unaffected_by_key_rotation(self):
        self.ingest([sealed_record("a")], key="k-1")
        _, before = self.receipt("k-1")
        request = urllib.request.Request(
            self.harness.base + "/v1/keys/rotate",
            data=json.dumps({"version": 2}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.receipt("k-1"), (200, before))

    # -- concurrency ------------------------------------------------------------

    def test_concurrent_same_key_commit_yields_404_or_complete_receipt(self):
        records = [sealed_record(f"r{i}") for i in range(3)]
        barrier = threading.Barrier(9)
        outcomes = []
        receipts = []

        def submit():
            barrier.wait()
            outcomes.append(self.ingest(copy.deepcopy(records), key="hot-key"))

        def query():
            barrier.wait()
            receipts.append(self.receipt("hot-key"))

        threads = [threading.Thread(target=submit) for _ in range(8)]
        threads.append(threading.Thread(target=query))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        statuses = [status for status, _ in outcomes]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        status, receipt = receipts[0]
        if status == 404:
            self.assertEqual(receipt, {"error": "not_found"})
        else:
            # A visible binding is always the complete committed batch.
            self.assertEqual(status, 200)
            self.assertEqual(receipt["count"], 3)
            self.assertEqual(
                [item["id"] for item in receipt["results"]], ["r0", "r1", "r2"]
            )
        # After the race settles the receipt is the committed batch.
        status, settled = self.receipt("hot-key")
        self.assertEqual(status, 200)
        self.assertEqual(settled["count"], 3)

    # -- helpers ----------------------------------------------------------------

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
