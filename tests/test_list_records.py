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


def make_config(directory: Path) -> Config:
    return Config(directory / "ledger.sqlite3", 1, dict(KEY_MATERIAL))


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


class ListRecordsProtocolTests(unittest.TestCase):
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

    def create(self, record_id, plaintext="x", tenant="acme"):
        return self.request("POST", "/v1/records", {"id": record_id, "plaintext": plaintext}, tenant=tenant)

    def list(self, query="", tenant="acme"):
        path = "/v1/records" if not query else "/v1/records?" + query
        return self.request("GET", path, tenant=tenant)

    def request_raw(self, harness, path, tenant="acme"):
        headers = {"X-Tenant-ID": tenant} if tenant is not None else {}
        request = urllib.request.Request(harness.base + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def all_pages(self, first_query="", tenant="acme"):
        status, body = self.list(first_query, tenant=tenant)
        self.assertEqual(status, 200)
        seen = [item["id"] for item in body["items"]]
        cursor = body.get("next_cursor")
        pages = [body]
        limit_query = first_query if first_query.startswith("limit=") else ""
        while cursor:
            query = f"cursor={cursor}" + (f"&{limit_query}" if limit_query else "")
            status, page = self.list(query, tenant=tenant)
            self.assertEqual(status, 200)
            pages.append(page)
            seen.extend(item["id"] for item in page["items"])
            cursor = page.get("next_cursor")
        return seen, pages

    # -- success -----------------------------------------------------------

    def test_empty_tenant_returns_empty_page_without_cursor(self):
        self.assertEqual(self.list(), (200, {"items": []}))

    def test_items_sorted_by_id_and_last_page_has_no_cursor(self):
        for record_id in ("b", "a", "c", "A", "Z", "1", "_", "-"):
            self.assertEqual(self.create(record_id)[0], 201)
        status, body = self.list("limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in body["items"]],
            ["-", "1", "A", "Z", "_", "a", "b", "c"],
        )
        self.assertNotIn("next_cursor", body)
        self.assertEqual(set(body), {"items"})
        for item in body["items"]:
            self.assertEqual(set(item), {"id"})

    def test_default_limit_is_fifty(self):
        for index in range(51):
            self.create(f"r{index:03d}")
        status, first = self.list()
        self.assertEqual(status, 200)
        self.assertEqual(len(first["items"]), 50)
        self.assertIn("next_cursor", first)
        status, second = self.list(f"cursor={first['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in second["items"]], ["r050"])
        self.assertNotIn("next_cursor", second)

    def test_pagination_walks_every_id_once_without_gaps(self):
        ids = [f"id-{index:04d}" for index in range(125)]
        for record_id in ids:
            self.create(record_id)
        seen, pages = self.all_pages("limit=20")
        self.assertEqual(len(pages), 7)
        self.assertEqual([len(page["items"]) for page in pages], [20, 20, 20, 20, 20, 20, 5])
        self.assertEqual(seen, sorted(ids))
        self.assertEqual(len(seen), len(set(seen)))

    def test_page_size_equal_to_total_is_single_page(self):
        for index in range(3):
            self.create(f"r{index}")
        status, body = self.list("limit=3")
        self.assertEqual((status, [item["id"] for item in body["items"]]), (200, ["r0", "r1", "r2"]))
        self.assertNotIn("next_cursor", body)

    def test_limit_boundaries_accepted_and_rejected(self):
        for index in range(2):
            self.create(f"r{index}")
        for value in ("1", "01", "007", "100"):
            self.assertEqual(self.list(f"limit={value}")[0], 200, value)
        for value in ("0", "101", "1000", "-1", "1.5", "0x1", "%201", "1%20", "", "a", "%EF%BC%95", "true"):
            status, body = self.list(f"limit={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_duplicate_limit_or_cursor_is_rejected(self):
        self.create("a")
        self.assertEqual(self.list("limit=1&limit=1"), (400, {"error": "invalid_request"}))
        self.assertEqual(self.list("limit=1&limit=1&cursor=x"), (400, {"error": "invalid_request"}))

    def test_unknown_query_parameters_are_ignored(self):
        self.create("a")
        status, body = self.list("foo=bar&baz=&limit=100&order=desc")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in body["items"]], ["a"])

    def test_64_char_identifier_is_listed(self):
        long_id = "z" * 64
        self.create(long_id)
        status, body = self.list()
        self.assertEqual((status, body), (200, {"items": [{"id": long_id}]}))

    def test_tenants_are_independent_snapshots(self):
        for index in range(5):
            self.create(f"a{index}", tenant="alpha")
        for index in range(3):
            self.create(f"b{index}", tenant="beta")
        alpha, _ = self.all_pages("limit=2", tenant="alpha")
        beta, _ = self.all_pages("limit=2", tenant="beta")
        self.assertEqual(alpha, [f"a{index}" for index in range(5)])
        self.assertEqual(beta, [f"b{index}" for index in range(3)])

    # -- snapshot semantics ------------------------------------------------

    def test_snapshot_excludes_later_creates_until_fresh_listing(self):
        for index in range(3):
            self.create(f"r{index}")
        status, first = self.list("limit=2")
        self.assertEqual([item["id"] for item in first["items"]], ["r0", "r1"])
        cursor = first["next_cursor"]

        self.create("new1")
        self.create("new2")
        self.request("POST", "/v1/keys/rotate", {"version": 2})

        status, second = self.list(f"cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in second["items"]], ["r2"])
        self.assertNotIn("next_cursor", second)

        # The same cursor is replayable and still pinned to the old snapshot.
        status, replay = self.list(f"cursor={cursor}")
        self.assertEqual([item["id"] for item in replay["items"]], ["r2"])

        # A fresh listing without a cursor sees the current snapshot.
        seen, _ = self.all_pages("limit=2")
        self.assertEqual(seen, sorted(["r0", "r1", "r2", "new1", "new2"]))

    def test_damaged_envelope_still_listed_but_read_fails(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.directory / "ledger.sqlite3")
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()

        seen, _ = self.all_pages("limit=1")
        self.assertEqual(seen, ["bad", "good"])
        self.assertEqual(self.request("GET", "/v1/records/bad", tenant="acme"),
                         (422, {"error": "integrity_error"}))
        self.assertEqual(self.request("GET", "/v1/records/good", tenant="acme")[0], 200)

    # -- cursor validation -------------------------------------------------

    def test_missing_or_invalid_tenant_is_rejected(self):
        self.assertEqual(self.list(tenant=None), (400, {"error": "invalid_request"}))
        self.assertEqual(self.list("limit=1", tenant="bad tenant!"),
                         (400, {"error": "invalid_request"}))

    def test_malformed_cursors_are_rejected_with_no_partial_page(self):
        for index in range(4):
            self.create(f"r{index}")
        valid_cursor = self.list("limit=2")[1]["next_cursor"]
        body, tag = valid_cursor.split(".", 1)

        def corrupt_tag_token(encoded_tag: str) -> str:
            # Flip a bit guaranteed to be significant (the first tag byte's
            # top bit); editing only the trailing base64 char is a no-op when
            # that char's significant bits happen to be zero.
            pad = "=" * (-len(encoded_tag) % 4)
            raw = bytearray(base64.urlsafe_b64decode(encoded_tag + pad))
            raw[0] ^= 0x80
            return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

        def corrupt_cursor(cursor: str) -> str:
            cursor_body, cursor_tag = cursor.split(".", 1)
            return cursor_body + "." + corrupt_tag_token(cursor_tag)

        cases = [
            "",
            "not-a-cursor",
            "a.b.c",
            body + "." + corrupt_tag_token(tag),
            "YWJj." + tag,
            corrupt_cursor(valid_cursor),
            valid_cursor + "%20",
            "cursor%20value%20with%20space",
        ]
        for value in cases:
            status, payload = self.list(f"cursor={value}")
            self.assertEqual((status, payload), (400, {"error": "invalid_request"}), value)

    def test_cursor_from_other_tenant_is_rejected(self):
        for index in range(4):
            self.create(f"r{index}", tenant="alpha")
        cursor = self.list("limit=2", tenant="alpha")[1]["next_cursor"]
        self.assertEqual(self.list(f"cursor={cursor}", tenant="beta"),
                         (400, {"error": "invalid_request"}))

    def test_cursor_from_restarted_process_is_rejected(self):
        for index in range(3):
            self.create(f"r{index}")
        cursor = self.list("limit=2")[1]["next_cursor"]
        self.harness.close()
        restarted = ServerHarness(make_config(self.directory))
        self.harness = restarted
        try:
            status, body = self.request_raw(restarted, f"/v1/records?cursor={cursor}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}))
            # A fresh listing still works after restart.
            status, body = self.request_raw(restarted, "/v1/records")
            self.assertEqual((status, [item["id"] for item in body["items"]]),
                             (200, ["r0", "r1", "r2"]))
        finally:
            restarted.close()

    # -- storage failure ---------------------------------------------------

    def test_storage_failure_on_snapshot_query_is_503(self):
        self.create("a")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TABLE records")
        raw.close()
        self.assertEqual(self.list(), (503, {"error": "storage_error"}))

    def test_storage_failure_does_not_affect_pages_already_returned(self):
        for index in range(4):
            self.create(f"r{index}")
        first = self.list("limit=2")[1]
        cursor = first["next_cursor"]
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TABLE records")
        raw.close()
        # Existing cursor pages are frozen and need no further storage reads.
        status, second = self.list(f"cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in second["items"]], ["r2", "r3"])
        self.assertNotIn("next_cursor", second)
        # A fresh snapshot cannot be taken without the table.
        self.assertEqual(self.list(), (503, {"error": "storage_error"}))


if __name__ == "__main__":
    unittest.main()
