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


class BatchReadProtocolTests(unittest.TestCase):
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
        request = urllib.request.Request(self.harness.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def create(self, record_id, plaintext, tenant="acme"):
        return self.request("POST", "/v1/records", {"id": record_id, "plaintext": plaintext}, tenant=tenant)

    def read(self, record_id, tenant="acme"):
        return self.request("GET", f"/v1/records/{record_id}", None, tenant=tenant)

    def batch_read(self, ids, tenant="acme"):
        return self.request("POST", "/v1/records/batch/read", {"ids": ids}, tenant=tenant)

    # -- success -----------------------------------------------------------

    def test_items_returned_in_request_order_with_plaintext(self):
        cases = {
            "empty": "",
            "chinese": "中文内容",
            "emoji": "emoji 😀🎉 mixed",
            "newline": "line1\nline2\r\n\t结束",
            "ascii": "plain value",
        }
        for record_id, plaintext in cases.items():
            self.assertEqual(self.create(record_id, plaintext)[0], 201)
        ordered_ids = ["newline", "ascii", "empty", "emoji", "chinese"]
        status, body = self.batch_read(ordered_ids)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"items": [
                {"id": record_id, "plaintext": cases[record_id], "key_version": 1}
                for record_id in ordered_ids
            ]},
        )

    def test_single_item_batch_matches_single_read(self):
        self.create("doc", "秘密 payload")
        status, batch_body = self.batch_read(["doc"])
        self.assertEqual(status, 200)
        single_status, single_body = self.read("doc")
        self.assertEqual(single_status, 200)
        self.assertEqual(batch_body["items"], [single_body])

    def test_same_id_across_tenants_is_isolated(self):
        self.create("shared", "tenant-a", tenant="alpha")
        self.create("shared", "tenant-b", tenant="beta")
        self.assertEqual(self.batch_read(["shared"], tenant="alpha"),
                         (200, {"items": [{"id": "shared", "plaintext": "tenant-a", "key_version": 1}]}))
        self.assertEqual(self.batch_read(["shared"], tenant="beta"),
                         (200, {"items": [{"id": "shared", "plaintext": "tenant-b", "key_version": 1}]}))

    def test_64_char_identifier_and_max_batch_boundary(self):
        long_id = "A" * 64
        self.assertEqual(self.create(long_id, "long")[0], 201)
        for index in range(99):
            self.assertEqual(self.create(f"r{index}", f"p{index}")[0], 201)
        ids = [long_id] + [f"r{index}" for index in range(99)]
        self.assertEqual(len(ids), 100)
        status, body = self.batch_read(ids)
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], ids)
        self.assertEqual(len(body["items"]), 100)
        self.assertEqual(self.batch_read(ids + ["one_more"]),
                         (400, {"error": "invalid_request"}))

    # -- request validation ------------------------------------------------

    def test_invalid_requests(self):
        cases = [
            ({"ids": []}, "acme"),
            ({"ids": ["x"] * 101}, "acme"),
            ({"ids": ["ok", 7]}, "acme"),
            ({"ids": ["ok", None]}, "acme"),
            ({"ids": ["ok", ""]}, "acme"),
            ({"ids": ["bad.id"]}, "acme"),
            ({"ids": ["x" * 65]}, "acme"),
            ({"ids": ["dup", "dup"]}, "acme"),
            ({"ids": "ok"}, "acme"),
            ({"ids": {"a": 1}}, "acme"),
            ({}, "acme"),
            ({"note": "ignored"}, "acme"),
            ({"ids": ["ok"], "extra": 123}, "bad tenant!"),
        ]
        for body, tenant in cases:
            with self.subTest(body=body, tenant=tenant):
                self.assertEqual(self.request("POST", "/v1/records/batch/read", body, tenant),
                                 (400, {"error": "invalid_request"}))

    def test_syntax_and_shape_errors_are_invalid_request(self):
        self.create("ok", "x")
        for raw in ('{"ids":["ok"],', "not json at all", '["ok"]', "42", '{"ids":["ok"]}'):
            pass
        self.assertEqual(self.request("POST", "/v1/records/batch/read", '{"ids":["ok"],', "acme"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.request("POST", "/v1/records/batch/read", "not json", "acme"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.request("POST", "/v1/records/batch/read", ["ok"], "acme"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.request("POST", "/v1/records/batch/read", 42, "acme"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.request("POST", "/v1/records/batch/read", {"ids": ["ok"]}, None),
                         (400, {"error": "invalid_request"}))

    def test_extra_fields_are_ignored_on_success(self):
        self.create("ok", "x")
        status, body = self.request("POST", "/v1/records/batch/read",
                                    {"ids": ["ok"], "note": "ignored", "n": 1}, "acme")
        self.assertEqual((status, body),
                         (200, {"items": [{"id": "ok", "plaintext": "x", "key_version": 1}]}))

    # -- not found / integrity / storage -----------------------------------

    def test_missing_and_cross_tenant_ids_are_not_found(self):
        self.create("mine", "secret", tenant="alpha")
        self.assertEqual(self.batch_read(["absent"], tenant="alpha"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.batch_read(["mine"], tenant="beta"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.batch_read(["mine", "absent"], tenant="alpha"),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.batch_read(["absent", "mine"], tenant="alpha"),
                         (404, {"error": "not_found"}))

    def test_missing_id_with_damaged_envelope_still_returns_404(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.directory / "ledger.sqlite3")
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()
        # Existence is checked before any envelope is opened.
        self.assertEqual(self.batch_read(["good", "absent"]),
                         (404, {"error": "not_found"}))
        self.assertEqual(self.batch_read(["absent", "bad"]),
                         (404, {"error": "not_found"}))

    def test_damaged_envelope_returns_422_without_other_plaintext(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.directory / "ledger.sqlite3")
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()
        for ids in (["good", "bad"], ["bad", "good"]):
            with self.subTest(ids=ids):
                self.assertEqual(self.batch_read(ids),
                                 (422, {"error": "integrity_error"}))
        # Service keeps serving healthy requests; good record is still readable.
        self.assertEqual(self.request("GET", "/health", None, None)[0], 200)
        self.assertEqual(self.read("good"),
                         (200, {"id": "good", "plaintext": "fine", "key_version": 1}))
        self.assertEqual(self.create("after", "still works")[0], 201)

    def test_storage_failure_on_existence_query_is_503_and_service_recovers(self):
        self.create("doc", "x")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TABLE records")
        raw.close()
        self.assertEqual(self.batch_read(["doc"]),
                         (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute(
                "CREATE TABLE records ("
                "tenant TEXT NOT NULL, id TEXT NOT NULL, key_version INTEGER NOT NULL, "
                "nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, wrap_nonce BLOB NOT NULL, "
                "wrapped_key BLOB NOT NULL, PRIMARY KEY (tenant, id))"
            )
        raw.close()
        self.assertEqual(self.create("later", "recovered")[0], 201)
        self.assertEqual(self.batch_read(["later"]),
                         (200, {"items": [{"id": "later", "plaintext": "recovered", "key_version": 1}]}))

    # -- concurrency -------------------------------------------------------

    def test_batch_read_concurrent_with_rotation_never_mixes_versions(self):
        for index in range(20):
            self.create(f"rec{index}", f"payload {index}")
        barrier = threading.Barrier(9)
        mixed = []
        failures = []

        def batch_read():
            barrier.wait()
            for _ in range(25):
                status, body = self.batch_read([f"rec{index}" for index in range(20)])
                if status == 200:
                    versions = {item["key_version"] for item in body["items"]}
                    if versions not in ({1}, {2}):
                        mixed.append(versions)
                elif status != 503:
                    failures.append((status, body))

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
            if status != 200:
                failures.append((status, body))

        threads = [threading.Thread(target=batch_read) for _ in range(8)]
        threads.append(threading.Thread(target=rotate))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(mixed, [])
        self.assertEqual(failures, [])
        status, body = self.batch_read([f"rec{index}" for index in range(20)])
        self.assertEqual(status, 200)
        self.assertEqual({item["key_version"] for item in body["items"]}, {2})
        self.assertEqual([item["plaintext"] for item in body["items"]],
                         [f"payload {index}" for index in range(20)])

    def test_batch_read_concurrent_with_create_sees_before_or_after_state(self):
        self.create("stable", "s")
        outcomes = []
        lock = threading.Lock()

        def batch_read():
            for _ in range(100):
                status, body = self.batch_read(["stable", "racing"])
                with lock:
                    if status == 404:
                        outcomes.append(404)
                    elif status == 200 and {item["id"] for item in body["items"]} == {"stable", "racing"}:
                        outcomes.append(200)

        def create():
            self.create("racing", "r")

        reader = threading.Thread(target=batch_read)
        reader.start()
        creator = threading.Thread(target=create)
        creator.start()
        creator.join()
        reader.join()
        self.assertTrue(outcomes)
        self.assertTrue(set(outcomes) <= {200, 404})
        self.assertEqual(self.batch_read(["stable", "racing"])[0], 200)

    def test_parallel_batch_reads_all_see_consistent_records(self):
        records = {f"rec{index}": f"payload {index} 内容" for index in range(10)}
        for record_id, plaintext in records.items():
            self.create(record_id, plaintext)
        ids = list(records)
        failures = []

        def batch_read():
            status, body = self.batch_read(ids)
            if status != 200:
                failures.append((status, body))
                return
            got = {item["id"]: item["plaintext"] for item in body["items"]}
            if got != records or [item["id"] for item in body["items"]] != ids:
                failures.append(body)

        threads = [threading.Thread(target=batch_read) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
