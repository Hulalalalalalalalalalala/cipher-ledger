import base64
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cipher_ledger.config import load_config
from cipher_ledger.server import LedgerServer


def make_keyring(directory: Path, active: int = 1, versions=(1, 2, 3)) -> Path:
    path = Path(directory) / "keyring.json"
    path.write_text(json.dumps({
        "active_version": active,
        "keys": {str(v): base64.b64encode(os.urandom(32)).decode() for v in versions},
    }))
    return path


class ServerFixture:
    def __init__(self, directory: Path, keyring: Path):
        self.directory = Path(directory)
        self.database = self.directory / "ledger.sqlite3"
        self.config = load_config(self.database, keyring)
        self.server = LedgerServer(("127.0.0.1", 0), self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def request(self, method, path, body=None, tenant=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if tenant is not None:
            request.add_header("X-Tenant-ID", tenant)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.load(error)
            finally:
                error.close()


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.keyring = make_keyring(Path(self.tempdir.name))
        self.fixture = ServerFixture(self.tempdir.name, self.keyring)
        self.addCleanup(self.fixture.close)

    def request(self, *args, **kwargs):
        return self.fixture.request(*args, **kwargs)

    def test_create_and_read_roundtrip_preserves_text(self):
        samples = ["", "plain ascii", "中文正文", "emoji 🚀🔐", "line one\nline two\n", "  padded  "]
        for index, text in enumerate(samples):
            status, body = self.request("POST", "/v1/records", {"id": f"rec_{index}", "plaintext": text}, tenant="acme")
            self.assertEqual(status, 201, body)
            self.assertEqual(body, {"id": f"rec_{index}", "key_version": 1})
            status, body = self.request("GET", f"/v1/records/rec_{index}", tenant="acme")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["plaintext"], text)
            self.assertEqual(body["key_version"], 1)

    def test_max_size_plaintext_accepted_and_larger_rejected(self):
        text = "密" * 20000  # 60000 UTF-8 bytes
        status, _ = self.request("POST", "/v1/records", {"id": "big", "plaintext": text}, tenant="acme")
        self.assertEqual(status, 201)
        status, body = self.request("GET", "/v1/records/big", tenant="acme")
        self.assertEqual(body["plaintext"], text)
        too_big = "x" * 65537
        status, body = self.request("POST", "/v1/records", {"id": "huge", "plaintext": too_big}, tenant="acme")
        self.assertEqual((status, body), (400, {"error": "invalid_request"}))

    def test_duplicate_create_conflicts_and_preserves_original(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "first"}, tenant="acme")
        status, body = self.request("POST", "/v1/records", {"id": "a", "plaintext": "second"}, tenant="acme")
        self.assertEqual((status, body), (409, {"error": "conflict"}))
        _, body = self.request("GET", "/v1/records/a", tenant="acme")
        self.assertEqual(body["plaintext"], "first")

    def test_tenants_are_isolated(self):
        self.request("POST", "/v1/records", {"id": "shared", "plaintext": "tenant a"}, tenant="alpha")
        status, body = self.request("POST", "/v1/records", {"id": "shared", "plaintext": "tenant b"}, tenant="beta")
        self.assertEqual(status, 201)
        _, body_a = self.request("GET", "/v1/records/shared", tenant="alpha")
        _, body_b = self.request("GET", "/v1/records/shared", tenant="beta")
        self.assertEqual(body_a["plaintext"], "tenant a")
        self.assertEqual(body_b["plaintext"], "tenant b")
        status, body = self.request("GET", "/v1/records/shared", tenant="gamma")
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_missing_record_is_not_found(self):
        status, body = self.request("GET", "/v1/records/ghost", tenant="acme")
        self.assertEqual((status, body), (404, {"error": "not_found"}))

    def test_invalid_requests(self):
        cases = [
            ("POST", "/v1/records", {"id": "a", "plaintext": "x"}, None),  # no tenant
            ("POST", "/v1/records", {"id": "a", "plaintext": "x"}, "bad tenant!"),
            ("POST", "/v1/records", {"id": "", "plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": "bad id", "plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": "a"}, "acme"),
            ("POST", "/v1/records", {"plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": "a", "plaintext": 5}, "acme"),
            ("GET", "/v1/records/a", None, None),
            ("GET", "/v1/records/bad%20id", None, "acme"),
        ]
        for method, path, body, tenant in cases:
            status, reply = self.request(method, path, body, tenant)
            self.assertEqual((status, reply), (400, {"error": "invalid_request"}), (method, path, body, tenant))

    def test_keys_endpoint_reports_active_version(self):
        status, body = self.request("GET", "/v1/keys")
        self.assertEqual((status, body), (200, {"active_version": 1}))

    def test_rotation_rewraps_everything_and_keeps_records_readable(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "alpha"}, tenant="t1")
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "beta"}, tenant="t2")
        before = self._raw_records()
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 3})
        self.assertEqual((status, body), (200, {"active_version": 3, "rewrapped": 2}))
        after = self._raw_records()
        for key in before:
            self.assertEqual(before[key]["nonce"], after[key]["nonce"])
            self.assertEqual(before[key]["ciphertext"], after[key]["ciphertext"])
            self.assertNotEqual(before[key]["wrapped_key"], after[key]["wrapped_key"])
            self.assertEqual(after[key]["key_version"], 3)
        _, body = self.request("GET", "/v1/records/a", tenant="t1")
        self.assertEqual((body["plaintext"], body["key_version"]), ("alpha", 3))
        _, body = self.request("GET", "/v1/records/a", tenant="t2")
        self.assertEqual((body["plaintext"], body["key_version"]), ("beta", 3))
        status, body = self.request("POST", "/v1/records", {"id": "new", "plaintext": "fresh"}, tenant="t1")
        self.assertEqual(body["key_version"], 3)

    def test_rotation_idempotent_and_conflict_and_unknown_version(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "x"}, tenant="t1")
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 1})
        self.assertEqual((status, body), (200, {"active_version": 1, "rewrapped": 0}))
        self.request("POST", "/v1/keys/rotate", {"version": 2})
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 1})
        self.assertEqual((status, body), (409, {"error": "version_conflict"}))
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 99})
        self.assertEqual((status, body), (400, {"error": "invalid_version"}))
        for bad in (True, "2", 2.5, 0, -1, None):
            status, body = self.request("POST", "/v1/keys/rotate", {"version": bad})
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), bad)

    def test_rotation_on_empty_database(self):
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual((status, body), (200, {"active_version": 2, "rewrapped": 0}))

    def test_tampered_envelope_is_rejected_and_service_survives(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "safe"}, tenant="t1")
        self.request("POST", "/v1/records", {"id": "b", "plaintext": "sound"}, tenant="t1")
        connection = sqlite3.connect(self.fixture.database)
        try:
            row = connection.execute("SELECT ciphertext FROM records WHERE id='a'").fetchone()
            flipped = bytes([row[0][0] ^ 1]) + row[0][1:]
            connection.execute("UPDATE records SET ciphertext=? WHERE id='a'", (flipped,))
            connection.commit()
        finally:
            connection.close()
        status, body = self.request("GET", "/v1/records/a", tenant="t1")
        self.assertEqual((status, body), (422, {"error": "integrity_error"}))
        status, body = self.request("GET", "/v1/records/b", tenant="t1")
        self.assertEqual((status, body["plaintext"]), (200, "sound"))

    def test_rotation_rejects_corrupted_envelope_without_partial_changes(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "one"}, tenant="t1")
        self.request("POST", "/v1/records", {"id": "b", "plaintext": "two"}, tenant="t1")
        connection = sqlite3.connect(self.fixture.database)
        try:
            row = connection.execute("SELECT wrapped_key FROM records WHERE id='b'").fetchone()
            flipped = bytes([row[0][0] ^ 1]) + row[0][1:]
            connection.execute("UPDATE records SET wrapped_key=? WHERE id='b'", (flipped,))
            connection.commit()
        finally:
            connection.close()
        corrupted = self._raw_records()
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual((status, body), (422, {"error": "integrity_error"}))
        self.assertEqual(corrupted, self._raw_records())
        _, body = self.request("GET", "/v1/keys")
        self.assertEqual(body["active_version"], 1)

    def test_storage_failure_rolls_back_rotation(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "one"}, tenant="t1")
        before = self._raw_records()
        connection = sqlite3.connect(self.fixture.database)
        try:
            connection.execute(
                "CREATE TRIGGER block_update BEFORE UPDATE ON records "
                "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
            )
            connection.commit()
        finally:
            connection.close()
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual((status, body), (503, {"error": "storage_error"}))
        self.assertEqual(before, self._raw_records())
        _, body = self.request("GET", "/v1/keys")
        self.assertEqual(body["active_version"], 1)
        connection = sqlite3.connect(self.fixture.database)
        try:
            connection.execute("DROP TRIGGER block_update")
            connection.commit()
        finally:
            connection.close()
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual((status, body), (200, {"active_version": 2, "rewrapped": 1}))

    def test_state_survives_restart_and_old_keys_can_be_removed(self):
        self.request("POST", "/v1/records", {"id": "a", "plaintext": "durable 中文"}, tenant="t1")
        self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.fixture.close()
        # Restart with a keyring whose initial active version is stale and
        # whose unreferenced old keys were removed.
        original = json.loads(Path(self.keyring).read_text())
        keyring = Path(self.tempdir.name) / "trimmed.json"
        keyring.write_text(json.dumps({"active_version": 2, "keys": {"2": original["keys"]["2"]}}))
        fixture = ServerFixture(self.tempdir.name, keyring)
        self.addCleanup(fixture.close)
        status, body = fixture.request("GET", "/v1/keys")
        self.assertEqual((status, body), (200, {"active_version": 2}))
        status, body = fixture.request("GET", "/v1/records/a", tenant="t1")
        self.assertEqual((status, body["plaintext"], body["key_version"]), (200, "durable 中文", 2))

    def test_concurrent_creates_only_one_wins(self):
        results = []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            results.append(self.request("POST", "/v1/records", {"id": "race", "plaintext": "x"}, tenant="t1")[0])

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def _raw_records(self):
        connection = sqlite3.connect(self.fixture.database)
        try:
            rows = connection.execute(
                "SELECT tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key FROM records"
            ).fetchall()
            return {
                (tenant, rid): {
                    "key_version": version,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "wrap_nonce": wrap_nonce,
                    "wrapped_key": wrapped_key,
                }
                for tenant, rid, version, nonce, ciphertext, wrap_nonce, wrapped_key in rows
            }
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
