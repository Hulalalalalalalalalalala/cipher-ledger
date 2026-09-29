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

    def create(self, record_id, plaintext="x", tenant="acme"):
        return self.request(
            "POST", "/v1/records",
            {"id": record_id, "plaintext": plaintext}, tenant=tenant,
        )

    def list_path(self, query="", tenant="acme"):
        return self.request("GET", "/v1/records" + (f"?{query}" if query else ""), tenant=tenant)

    def list_all(self, query="", tenant="acme"):
        status, body = self.list_path(query, tenant=tenant)
        if status != 200:
            return status, body
        ids = list(body["items"])
        while "next_cursor" in body:
            status, body = self.list_path(f"cursor={body['next_cursor']}", tenant=tenant)
            if status != 200:
                return status, body
            ids.extend(body["items"])
        return 200, ids

    def create_many(self, count, tenant="acme"):
        created = []
        for start in range(0, count, 100):
            records = [
                {"id": f"rec-{index:04d}", "plaintext": str(index)}
                for index in range(start, min(start + 100, count))
            ]
            status, body = self.request(
                "POST", "/v1/records/batch", {"records": records}, tenant=tenant
            )
            self.assertEqual(status, 201, body)
            created.extend(body["created"])
        return created

    # -- basic listing ------------------------------------------------------

    def test_empty_tenant_returns_empty_page_without_cursor(self):
        self.assertEqual(self.list_path(), (200, {"items": []}))

    def test_single_page_contains_only_ids_in_sorted_order(self):
        # Insert out of order; listing order is a stable id order.
        for record_id in ("zeta", "alpha", "mu", "beta-1", "beta-0", "a_1", "a1"):
            self.assertEqual(self.create(record_id)[0], 201)
        status, body = self.list_path("limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"items": ["a1", "a_1", "alpha", "beta-0", "beta-1", "mu", "zeta"]},
        )
        self.assertNotIn("plaintext", json.dumps(body))
        self.assertNotIn("key_version", json.dumps(body))

    def test_default_limit_is_fifty(self):
        ids = self.create_many(60)
        status, body = self.list_path()
        self.assertEqual((status, len(body["items"])), (200, 50))
        self.assertIn("next_cursor", body)

    def test_limit_boundaries_one_and_one_hundred(self):
        ids = self.create_many(100)
        status, body = self.list_path("limit=1")
        self.assertEqual((status, body["items"]), (200, ids[:1]))
        self.assertIn("next_cursor", body)
        status, body = self.list_path("limit=100")
        self.assertEqual((status, len(body["items"])), (200, 100))
        self.assertNotIn("next_cursor", body)

    def test_full_page_exact_multiple_has_no_cursor_on_last_page(self):
        self.create_many(10)
        status, body = self.list_path("limit=5")
        self.assertEqual((status, len(body["items"])), (200, 5))
        self.assertIn("next_cursor", body)
        status, body = self.list_path(f"cursor={body['next_cursor']}")
        self.assertEqual((status, len(body["items"])), (200, 5))
        self.assertNotIn("next_cursor", body)

    def test_pagination_covers_every_id_once_in_order(self):
        ids = sorted(self.create_many(125))
        for limit in (1, 7, 50, 100, 63):
            status, collected = self.list_all(f"limit={limit}")
            self.assertEqual(status, 200)
            self.assertEqual(collected, ids, limit)

    def test_limit_can_change_between_pages(self):
        ids = sorted(self.create_many(10))
        status, body = self.list_path("limit=3")
        seen = body["items"]
        status, body = self.list_path(f"cursor={body['next_cursor']}&limit=4")
        seen += body["items"]
        status, body = self.list_path(f"cursor={body['next_cursor']}&limit=100")
        seen += body["items"]
        self.assertEqual((status, seen), (200, ids))
        self.assertNotIn("next_cursor", body)

    def test_sixty_four_char_id_is_listed(self):
        record_id = "a" * 64
        self.assertEqual(self.create(record_id)[0], 201)
        self.assertEqual(self.list_path(), (200, {"items": [record_id]}))

    def test_unknown_query_parameters_are_ignored(self):
        self.assertEqual(self.create("doc")[0], 201)
        status, body = self.list_path("foo=bar&limit=10&bogus=1%202")
        self.assertEqual((status, body), (200, {"items": ["doc"]}))

    # -- snapshot semantics -------------------------------------------------

    def test_snapshot_excludes_records_created_after_first_page(self):
        ids = sorted(self.create_many(10))
        status, page = self.list_path("limit=4")
        self.assertEqual(status, 200)
        # Created while paging the fixed snapshot; must never appear.
        self.create("aaa-new")
        self.create("zzz-new")
        status, body = self.list_path(f"cursor={page['next_cursor']}")
        seen = page["items"]
        while status == 200:
            seen += body["items"]
            if "next_cursor" not in body:
                break
            status, body = self.list_path(f"cursor={body['next_cursor']}")
        self.assertEqual((status, sorted(seen)), (200, ids))
        # A fresh snapshot without cursor sees the new records.
        status, fresh = self.list_all("limit=3")
        self.assertEqual(status, 200)
        self.assertEqual(fresh, ["aaa-new"] + ids + ["zzz-new"])

    def test_rotation_does_not_change_pages_and_damaged_envelope_still_lists(self):
        ids = sorted(self.create_many(8))
        status, page = self.list_path("limit=3")
        self.assertEqual(status, 200)
        status, _ = self.request("POST", "/v1/keys/rotate", {"version": 2}, tenant="acme")
        self.assertEqual(status, 200)
        # Damage one envelope: listing still returns the id, reading still fails.
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("UPDATE records SET ciphertext=zeroblob(length(ciphertext)) WHERE id='rec-0004'")
        raw.close()
        status, body = self.list_path(f"limit=1&cursor={page['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], ["rec-0003"])
        status, body = self.list_path(f"cursor={body['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"][0], "rec-0004")
        status, collected = self.list_all()
        self.assertEqual((status, collected), (200, ids))
        self.assertEqual(
            self.request("GET", "/v1/records/rec-0004"),
            (422, {"error": "integrity_error"}),
        )

    # -- tenant isolation ---------------------------------------------------

    def test_listing_is_scoped_per_tenant(self):
        self.create("shared", "a", tenant="alpha")
        self.create("alpha-only", "a", tenant="alpha")
        self.create("shared", "b", tenant="beta")
        self.assertEqual(self.list_all(tenant="alpha")[1], ["alpha-only", "shared"])
        self.assertEqual(self.list_path(tenant="beta")[1], {"items": ["shared"]})
        self.assertEqual(self.list_path(tenant="gamma"), (200, {"items": []}))

    def test_cursor_issued_for_other_tenant_is_rejected(self):
        self.create_many(5, tenant="alpha")
        _, page = self.list_path("limit=2", tenant="alpha")
        self.assertEqual(
            self.list_path(f"cursor={page['next_cursor']}", tenant="beta"),
            (400, {"error": "invalid_request"}),
        )
        # The rejected request did not consume or invalidate the cursor.
        status, body = self.list_path(f"cursor={page['next_cursor']}&limit=50", tenant="alpha")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [f"rec-{i:04d}" for i in range(2, 5)])
        self.assertNotIn("next_cursor", body)

    # -- validation errors --------------------------------------------------

    def test_missing_or_invalid_tenant_is_400(self):
        self.assertEqual(self.list_path(tenant=None), (400, {"error": "invalid_request"}))
        for bad_tenant in ("bad tenant", "a/b", "é", "a" * 65):
            self.assertEqual(
                self.list_path(tenant=bad_tenant),
                (400, {"error": "invalid_request"}),
                bad_tenant,
            )

    def test_invalid_limits_are_400_without_partial_page(self):
        self.create_many(3)
        for limit in ("0", "101", "1000", "-1", "1.0", "01 ", " 1", "abc", "1a", "", "0x1", "+1"):
            self.assertEqual(
                self.list_path(f"limit={urllib.parse.quote(limit)}"),
                (400, {"error": "invalid_request"}),
                limit,
            )

    def test_repeated_limit_or_cursor_is_400(self):
        self.create_many(5)
        _, page = self.list_path("limit=2")
        cursor = page["next_cursor"]
        self.assertEqual(self.list_path("limit=1&limit=2"), (400, {"error": "invalid_request"}))
        self.assertEqual(
            self.list_path(f"cursor={cursor}&cursor={cursor}"),
            (400, {"error": "invalid_request"}),
        )

    def test_malformed_cursor_is_400(self):
        for token in ("not-a-cursor", "!!!", "AAAA", "", "e30%3D"):
            self.assertEqual(
                self.list_path(f"cursor={token}"),
                (400, {"error": "invalid_request"}),
                token,
            )

    def test_tampered_cursor_signature_is_400(self):
        self.create_many(3)
        _, page = self.list_path("limit=1")
        cursor = page["next_cursor"]
        flipped = ("B" if cursor[-1] == "A" else "A") + cursor[1:]
        self.assertEqual(self.list_path(f"cursor={flipped}"), (400, {"error": "invalid_request"}))
        # Padding appended after the unpadded token is itself malformed.
        self.assertEqual(self.list_path(f"cursor={cursor}."), (400, {"error": "invalid_request"}))

    # -- storage failure ----------------------------------------------------

    def test_storage_failure_is_503_and_recovers(self):
        self.create_many(3)
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TABLE records")
        raw.close()
        self.assertEqual(self.list_path(), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute(
                "CREATE TABLE records ("
                "tenant TEXT NOT NULL, id TEXT NOT NULL, key_version INTEGER NOT NULL, "
                "nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, wrap_nonce BLOB NOT NULL, "
                "wrapped_key BLOB NOT NULL, PRIMARY KEY (tenant, id))"
            )
        raw.close()
        self.assertEqual(self.list_path(), (200, {"items": []}))
        self.assertEqual(self.create("later", "recovered")[0], 201)


if __name__ == "__main__":
    unittest.main()
