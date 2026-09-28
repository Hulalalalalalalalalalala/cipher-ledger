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


class BatchRecordProtocolTests(unittest.TestCase):
    PATH = "/v1/records/batch"

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

    def batch(self, records, tenant="acme"):
        return self.request("POST", self.PATH, {"records": records}, tenant=tenant)

    def create(self, record_id, plaintext, tenant="acme"):
        return self.request(
            "POST", "/v1/records",
            {"id": record_id, "plaintext": plaintext}, tenant=tenant,
        )

    def read(self, record_id, tenant="acme"):
        return self.request("GET", f"/v1/records/{record_id}", tenant=tenant)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    # -- success -----------------------------------------------------------

    def test_batch_success_response_and_order(self):
        records = [
            {"id": "invoice_2", "plaintext": "second"},
            {"id": "invoice_1", "plaintext": "first"},
        ]
        status, body = self.batch(records)
        self.assertEqual(status, 201)
        self.assertEqual(body, {"key_version": 1, "created": ["invoice_2", "invoice_1"]})
        self.assertEqual(self.read("invoice_1")[1]["plaintext"], "first")
        self.assertEqual(self.read("invoice_2")[1]["plaintext"], "second")

    def test_batch_preserves_empty_chinese_emoji_newline(self):
        cases = ("", "中文内容", "emoji 😀🎉 mixed", "line1\nline2\r\n\t结束", "😀" * 100)
        records = [{"id": f"r_{index}", "plaintext": value} for index, value in enumerate(cases)]
        self.assertEqual(self.batch(records)[0], 201)
        for index, value in enumerate(cases):
            self.assertEqual(self.read(f"r_{index}")[1]["plaintext"], value)

    def test_batch_uses_active_version_after_rotation(self):
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200)
        status, body = self.batch([{"id": "a", "plaintext": "x"}, {"id": "b", "plaintext": "y"}])
        self.assertEqual((status, body["key_version"]), (201, 2))
        raw = self.db()
        versions = {row[0] for row in raw.execute("SELECT DISTINCT key_version FROM records")}
        raw.close()
        self.assertEqual(versions, {2})

    def test_batch_independent_keys_and_nonces_and_envelope_shape(self):
        records = [{"id": f"id_{i}", "plaintext": f"payload {i} 密"} for i in range(5)]
        self.assertEqual(self.batch(records)[0], 201)
        raw = self.db()
        rows = raw.execute(
            "SELECT nonce, ciphertext, wrap_nonce, wrapped_key FROM records ORDER BY id"
        ).fetchall()
        raw.close()
        self.assertEqual(len(rows), 5)
        nonces = [bytes(row[0]) for row in rows]
        wrap_nonces = [bytes(row[2]) for row in rows]
        wrapped_keys = [bytes(row[3]) for row in rows]
        self.assertEqual(len(set(nonces)), 5)
        self.assertEqual(len(set(wrap_nonces)), 5)
        self.assertEqual(len(set(wrapped_keys)), 5)
        for row in rows:
            self.assertEqual([len(row[i]) for i in range(4)], [12, len("payload 0 密".encode()) + 16, 12, 48])

    def test_batch_extension_fields_ignored(self):
        records = [{"id": "a", "plaintext": "x", "extra": {"nested": [1, 2]}, "v": True}]
        status, body = self.batch(records)
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["a"]}))

    def test_batch_boundaries_one_and_one_hundred(self):
        self.assertEqual(self.batch([{"id": "only", "plaintext": ""}])[0], 201)
        records = [{"id": f"bulk_{i:03d}", "plaintext": "中"} for i in range(100)]
        self.assertEqual(self.batch(records)[0], 201)
        raw = self.db()
        count = raw.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        raw.close()
        self.assertEqual(count, 101)

    # -- request validation ------------------------------------------------

    def assert_invalid(self, body, tenant="acme"):
        self.assertEqual(
            self.request("POST", self.PATH, body=body, tenant=tenant),
            (400, {"error": "invalid_request"}),
        )

    def test_invalid_tenant(self):
        body = {"records": [{"id": "a", "plaintext": "x"}]}
        self.assert_invalid(body, tenant=None)
        self.assert_invalid(body, tenant="bad tenant!")

    def test_invalid_bodies(self):
        self.assert_invalid("not json at all")
        self.assert_invalid('{"records": [')
        self.assert_invalid(["records"])
        self.assert_invalid(42)
        self.assert_invalid({})
        self.assert_invalid({"records": {}})
        self.assert_invalid({"records": "x"})
        self.assert_invalid({"records": None})
        self.assert_invalid({"records": []})
        self.assert_invalid({"records": [{"id": f"x{i}", "plaintext": "x"} for i in range(101)]})

    def test_invalid_entries(self):
        self.assert_invalid({"records": [{"id": "a", "plaintext": "x"}, {"id": "b"}]})
        self.assert_invalid({"records": [{"plaintext": "x"}]})
        self.assert_invalid({"records": [{"id": "a"}]})
        self.assert_invalid({"records": [{"id": 7, "plaintext": "x"}]})
        self.assert_invalid({"records": [{"id": "", "plaintext": "x"}]})
        self.assert_invalid({"records": [{"id": "x" * 65, "plaintext": "x"}]})
        self.assert_invalid({"records": [{"id": "bad.id", "plaintext": "x"}]})
        self.assert_invalid({"records": [{"id": "a", "plaintext": 42}]})
        self.assert_invalid({"records": [{"id": "a", "plaintext": None}]})
        self.assert_invalid({"records": [{"id": "a", "plaintext": ["x"]}]})
        self.assert_invalid({"records": [42]})
        self.assert_invalid({"records": ["a"]})
        self.assert_invalid({"records": [None]})
        self.assert_invalid(
            {"records": [{"id": "ok", "plaintext": "x"}, {"id": "bad", "plaintext": "a" * 65537}]}
        )

    def test_plaintext_byte_limit_boundaries(self):
        exact = [{"id": "exact", "plaintext": "a" * 65536}]
        self.assertEqual(self.batch(exact)[0], 201)
        over_multibyte = [{"id": "multi", "plaintext": "中" * 21846}]
        self.assertEqual(self.batch(over_multibyte), (400, {"error": "invalid_request"}))

    def test_invalid_batch_leaves_nothing(self):
        body = {"records": [
            {"id": "good", "plaintext": "x"},
            {"id": "bad", "plaintext": ["nope"]},
        ]}
        self.assertEqual(self.request("POST", self.PATH, body), (400, {"error": "invalid_request"}))
        raw = self.db()
        count = raw.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        raw.close()
        self.assertEqual(count, 0)

    # -- conflict and isolation -------------------------------------------

    def test_duplicate_id_within_batch_conflicts_and_nothing_written(self):
        body = {"records": [
            {"id": "a", "plaintext": "first"},
            {"id": "b", "plaintext": "second"},
            {"id": "a", "plaintext": "third"},
        ]}
        self.assertEqual(self.request("POST", self.PATH, body), (409, {"error": "conflict"}))
        raw = self.db()
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        raw.close()

    def test_existing_id_conflicts_and_batch_fully_aborted(self):
        self.assertEqual(self.create("existing", "old value")[0], 201)
        body = {"records": [
            {"id": "new_1", "plaintext": "one"},
            {"id": "existing", "plaintext": "two"},
            {"id": "new_2", "plaintext": "three"},
        ]}
        self.assertEqual(self.request("POST", self.PATH, body), (409, {"error": "conflict"}))
        self.assertEqual(self.read("existing")[1]["plaintext"], "old value")
        self.assertEqual(self.read("new_1")[0], 404)
        self.assertEqual(self.read("new_2")[0], 404)

    def test_same_id_across_tenants_is_independent(self):
        body = {"records": [{"id": "shared", "plaintext": "tenant-a"}, {"id": "other", "plaintext": "a2"}]}
        self.assertEqual(self.request("POST", self.PATH, body, tenant="alpha")[0], 201)
        body = {"records": [{"id": "shared", "plaintext": "tenant-b"}, {"id": "other", "plaintext": "b2"}]}
        self.assertEqual(self.request("POST", self.PATH, body, tenant="beta")[0], 201)
        self.assertEqual(self.read("shared", tenant="alpha")[1]["plaintext"], "tenant-a")
        self.assertEqual(self.read("shared", tenant="beta")[1]["plaintext"], "tenant-b")

    def test_conflict_is_checked_per_tenant(self):
        self.create("only_here", "x", tenant="alpha")
        self.assertEqual(
            self.batch([{"id": "only_here", "plaintext": "y"}], tenant="beta")[0], 201
        )

    def test_single_and_batch_share_namespace(self):
        self.create("singleton", "v1")
        self.assertEqual(
            self.batch([{"id": "singleton", "plaintext": "v2"}]),
            (409, {"error": "conflict"}),
        )

    # -- storage failure ---------------------------------------------------

    def test_storage_failure_aborts_whole_batch(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_records_insert BEFORE INSERT ON records "
                "BEGIN INSERT INTO missing_table VALUES (1); END"
            )
        raw.close()
        body = {"records": [{"id": f"r{i}", "plaintext": f"p{i}"} for i in range(5)]}
        self.assertEqual(self.request("POST", self.PATH, body), (503, {"error": "storage_error"}))
        raw = self.db()
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        with raw:
            raw.execute("DROP TRIGGER block_records_insert")
        raw.close()
        self.assertEqual(
            self.batch([{"id": "recovered", "plaintext": "ok"}]),
            (201, {"key_version": 1, "created": ["recovered"]}),
        )

    # -- concurrency -------------------------------------------------------

    def test_concurrent_batches_same_ids_single_winner(self):
        barrier = threading.Barrier(8)
        results = []

        def run():
            barrier.wait()
            records = [{"id": f"race{i}", "plaintext": f"p{i}"} for i in range(3)]
            results.append(self.batch(records)[0])

        threads = [threading.Thread(target=run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(409), 7)
        raw = self.db()
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 3)
        rows = raw.execute("SELECT id FROM records ORDER BY id").fetchall()
        self.assertEqual([row[0] for row in rows], ["race0", "race1", "race2"])
        raw.close()

    def test_concurrent_batch_and_single_creates_single_winner(self):
        barrier = threading.Barrier(6)
        results = []

        def run_batch():
            barrier.wait()
            results.append(self.batch([{"id": "shared", "plaintext": "batch"}])[0])

        def run_single():
            barrier.wait()
            results.append(self.create("shared", "single")[0])

        threads = [threading.Thread(target=run_batch)]
        threads.extend(threading.Thread(target=run_single) for _ in range(5))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(409), 5)

    def test_batch_concurrent_with_rotation_all_final_version(self):
        for i in range(5):
            self.create(f"old{i}", f"old {i}")
        barrier = threading.Barrier(2)
        failures = []

        def run_batch():
            barrier.wait()
            status, body = self.batch(
                [{"id": f"new{i}", "plaintext": f"new {i} 内容"} for i in range(5)]
            )
            if status != 201:
                failures.append((status, body))

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
            if status != 200:
                failures.append((status, body))

        threads = [
            threading.Thread(target=run_batch),
            threading.Thread(target=rotate),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(self.request("GET", "/v1/keys")[1], {"active_version": 2})
        raw = self.db()
        versions = {row[0] for row in raw.execute("SELECT DISTINCT key_version FROM records")}
        count = raw.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        raw.close()
        self.assertEqual(versions, {2})
        self.assertEqual(count, 10)
        for i in range(5):
            status, body = self.read(f"new{i}")
            self.assertEqual(status, 200)
            self.assertEqual(body["plaintext"], f"new {i} 内容")
            self.assertEqual(body["key_version"], 2)


if __name__ == "__main__":
    unittest.main()
