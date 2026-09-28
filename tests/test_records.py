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


class RecordProtocolTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    def request(self, method, path, body=None, tenant=None):
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
        return self.request("GET", f"/v1/records/{record_id}", tenant=tenant)

    # -- basic round trips -------------------------------------------------

    def test_create_and_read_round_trip(self):
        status, body = self.create("invoice_1", "待保存文字")
        self.assertEqual((status, body), (201, {"id": "invoice_1", "key_version": 1}))
        status, body = self.read("invoice_1")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"id": "invoice_1", "plaintext": "待保存文字", "key_version": 1})

    def test_empty_chinese_emoji_newline_preserved(self):
        cases = ("", "中文内容", "emoji 😀🎉 mixed", "line1\nline2\r\n\t结束", "😀" * 100)
        for index, plaintext in enumerate(cases):
            record_id = f"r_{index}"
            self.assertEqual(self.create(record_id, plaintext)[0], 201)
            self.assertEqual(self.read(record_id)[1]["plaintext"], plaintext)

    def test_utf8_byte_length_boundaries(self):
        exact = "a" * 65536
        self.assertEqual(self.create("ok_ascii", exact)[0], 201)
        self.assertEqual(self.read("ok_ascii")[1]["plaintext"], exact)
        self.assertEqual(self.create("too_long_ascii", "a" * 65537)[1], {"error": "invalid_request"})
        multibyte = "中" * 21845 + "a"  # 21845*3 + 1 = 65536 bytes
        self.assertEqual(len(multibyte.encode("utf-8")), 65536)
        self.assertEqual(self.create("ok_multi", multibyte)[0], 201)
        self.assertEqual(self.create("too_long_multi", "中" * 21846)[0], 400)

    def test_duplicate_conflict_does_not_overwrite(self):
        self.assertEqual(self.create("dup", "first")[0], 201)
        status, body = self.create("dup", "second")
        self.assertEqual((status, body), (409, {"error": "conflict"}))
        self.assertEqual(self.read("dup")[1]["plaintext"], "first")

    def test_same_id_across_tenants_is_independent(self):
        self.assertEqual(self.create("shared", "tenant-a", tenant="alpha")[0], 201)
        self.assertEqual(self.create("shared", "tenant-b", tenant="beta")[0], 201)
        self.assertEqual(self.read("shared", tenant="alpha")[1]["plaintext"], "tenant-a")
        self.assertEqual(self.read("shared", tenant="beta")[1]["plaintext"], "tenant-b")

    def test_missing_and_cross_tenant_reads_are_not_found(self):
        self.create("mine", "secret", tenant="alpha")
        self.assertEqual(self.read("mine", tenant="beta"), (404, {"error": "not_found"}))
        self.assertEqual(self.read("absent", tenant="alpha"), (404, {"error": "not_found"}))

    def test_keys_endpoint_reports_active_version(self):
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))

    # -- request validation ------------------------------------------------

    def test_invalid_requests(self):
        cases = [
            ("POST", "/v1/records", {"id": "ok", "plaintext": "x"}, None),
            ("POST", "/v1/records", {"id": "ok", "plaintext": "x"}, "bad tenant!"),
            ("POST", "/v1/records", {"id": "", "plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": "x" * 65, "plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": 7, "plaintext": "x"}, "acme"),
            ("POST", "/v1/records", {"id": "ok", "plaintext": 42}, "acme"),
            ("POST", "/v1/records", {"id": "ok", "plaintext": None}, "acme"),
            ("POST", "/v1/records", '{"id":"ok","plaintext":"x",', "acme"),
            ("POST", "/v1/records", ["id", "ok"], "acme"),
            ("POST", "/v1/records", "not json at all", "acme"),
            ("POST", "/v1/records", 42, "acme"),
        ]
        for method, path, body, tenant in cases:
            with self.subTest(body=body, tenant=tenant):
                status, payload = self.request(method, path, body=body, tenant=tenant)
                self.assertEqual((status, payload), (400, {"error": "invalid_request"}))
        # invalid id in the path
        self.assertEqual(self.request("GET", "/v1/records/bad.id", tenant="acme"), (400, {"error": "invalid_request"}))
        self.assertEqual(self.request("GET", "/v1/records/ok", tenant=None), (400, {"error": "invalid_request"}))
        # 64-char identifier is accepted
        self.assertEqual(self.create("a" * 64, "x")[0], 201)

    def test_rotation_version_validation(self):
        status, body = self.request("POST", "/v1/keys/rotate", {"version": 9})
        self.assertEqual((status, body), (400, {"error": "invalid_version"}))
        for invalid in ({"version": "2"}, {"version": True}, {"version": 1.5}, {"version": 0}, {}, {"version": -1}, "x"):
            with self.subTest(invalid=invalid):
                self.assertEqual(self.request("POST", "/v1/keys/rotate", invalid)[1], {"error": "invalid_request"})

    # -- rotation ----------------------------------------------------------

    def test_rotation_rewraps_keys_only_and_count(self):
        for i in range(3):
            self.create(f"rec{i}", f"payload {i} 内容")
        db = connect(self.directory / "ledger.sqlite3")
        before = {r[0]: tuple(r[1:]) for r in db.execute(
            "SELECT id, nonce, ciphertext, wrap_nonce, wrapped_key FROM records ORDER BY id"
        )}
        db.close()

        status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual((status, body), (200, {"active_version": 2, "rewrapped": 3}))

        db = connect(self.directory / "ledger.sqlite3")
        rows = {r[0]: tuple(r[1:]) for r in db.execute(
            "SELECT id, nonce, ciphertext, wrap_nonce, wrapped_key, key_version FROM records ORDER BY id"
        )}
        db.close()
        for record_id, (nonce, ciphertext, wrap_nonce, wrapped_key) in before.items():
            new_nonce, new_ciphertext, new_wrap_nonce, new_wrapped, version = rows[record_id]
            self.assertEqual(new_nonce, nonce)
            self.assertEqual(new_ciphertext, ciphertext)
            self.assertEqual(version, 2)
            self.assertNotEqual(new_wrap_nonce, wrap_nonce)
            self.assertNotEqual(new_wrapped, wrapped_key)
            self.assertEqual(len(new_wrap_nonce), 12)
            self.assertEqual(len(new_wrapped), 48)

        for i in range(3):
            self.assertEqual(self.read(f"rec{i}")[1], {"id": f"rec{i}", "plaintext": f"payload {i} 内容", "key_version": 2})
        self.assertEqual(self.create("fresh", "new")[1]["key_version"], 2)

    def test_empty_database_rotation_and_skip_versions(self):
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 3}), (200, {"active_version": 3, "rewrapped": 0}))
        self.assertEqual(self.create("later", "sealed at three")[1]["key_version"], 3)
        self.assertEqual(self.read("later")[1]["key_version"], 3)

    def test_idempotent_same_version_changes_nothing(self):
        self.create("rec", "payload")
        first = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual(first, (200, {"active_version": 2, "rewrapped": 1}))
        db = connect(self.directory / "ledger.sqlite3")
        snapshot = db.execute("SELECT wrap_nonce, wrapped_key FROM records").fetchone()
        db.close()
        again = self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual(again, (200, {"active_version": 2, "rewrapped": 0}))
        db = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(tuple(db.execute("SELECT wrap_nonce, wrapped_key FROM records").fetchone()), tuple(snapshot))
        db.close()

    def test_version_rollback_rejected(self):
        self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 1}), (409, {"error": "version_conflict"}))
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 2}))

    def test_damaged_envelope_aborts_whole_rotation(self):
        self.create("good", "fine")
        self.create("bad", "also fine")
        raw = connect(self.directory / "ledger.sqlite3")
        blob = bytearray(raw.execute("SELECT ciphertext FROM records WHERE id='bad'").fetchone()[0])
        blob[0] ^= 0xFF
        with raw:
            raw.execute("UPDATE records SET ciphertext=? WHERE id='bad'", (bytes(blob),))
        raw.close()

        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2}), (422, {"error": "integrity_error"}))
        # Nothing moved: active version and all envelopes stay at v1.
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))
        self.assertEqual(self.read("good")[1]["key_version"], 1)
        self.assertEqual(self.read("bad"), (422, {"error": "integrity_error"}))

    def test_storage_failure_leaves_no_partial_rotation(self):
        for i in range(3):
            self.create(f"rec{i}", f"payload {i}")
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_records_update BEFORE UPDATE ON records "
                        "BEGIN SELECT RAISE(ABORT, 'rotations disabled'); END")
        raw.close()

        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2}), (503, {"error": "storage_error"}))
        self.assertEqual(self.request("GET", "/v1/keys"), (200, {"active_version": 1}))
        for i in range(3):
            self.assertEqual(self.read(f"rec{i}")[1]["key_version"], 1)

        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_records_update")
        raw.close()
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2}), (200, {"active_version": 2, "rewrapped": 3}))
        for i in range(3):
            self.assertEqual(self.read(f"rec{i}")[1]["plaintext"], f"payload {i}")

    # -- tamper protection -------------------------------------------------

    def test_any_field_tamper_is_rejected(self):
        self.create("doc", "secret value 密")
        raw = connect(self.directory / "ledger.sqlite3")
        original = {
            column: bytes(raw.execute(f"SELECT {column} FROM records WHERE id='doc'").fetchone()[0])
            for column in ("nonce", "ciphertext", "wrap_nonce", "wrapped_key")
        }
        try:
            for column, value in original.items():
                damaged = bytearray(value)
                damaged[0] ^= 0x01
                with raw:
                    raw.execute(f"UPDATE records SET {column}=? WHERE id='doc'", (bytes(damaged),))
                self.assertEqual(self.read("doc"), (422, {"error": "integrity_error"}), column)
                with raw:
                    raw.execute(f"UPDATE records SET {column}=? WHERE id='doc'", (value,))
                self.assertEqual(self.read("doc")[0], 200, column)

            with raw:
                raw.execute("UPDATE records SET key_version=2 WHERE id='doc'")
            self.assertEqual(self.read("doc"), (422, {"error": "integrity_error"}))
        finally:
            raw.close()
        # service keeps serving healthy requests after integrity failures
        self.assertEqual(self.request("GET", "/health")[0], 200)
        self.assertEqual(self.create("after", "still works")[0], 201)

    def test_envelope_moved_to_other_tenant_is_rejected(self):
        self.create("doc", "bound to alpha", tenant="alpha")
        raw = connect(self.directory / "ledger.sqlite3")
        row = raw.execute("SELECT key_version, nonce, ciphertext, wrap_nonce, wrapped_key FROM records").fetchone()
        with raw:
            raw.execute("INSERT INTO records (tenant, id, key_version, nonce, ciphertext, wrap_nonce, wrapped_key) "
                        "VALUES ('beta', 'doc', ?, ?, ?, ?, ?)", tuple(row))
        raw.close()
        self.assertEqual(self.read("doc", tenant="beta"), (422, {"error": "integrity_error"}))
        self.assertEqual(self.read("doc", tenant="alpha")[0], 200)

    # -- persistence -------------------------------------------------------

    def test_restart_keeps_records_and_database_active_version(self):
        self.create("rec1", "persist 内容")
        self.request("POST", "/v1/keys/rotate", {"version": 2})
        db_path = self.directory / "ledger.sqlite3"
        self.harness.close()

        # Stale config initial value (1) must lose to persisted value (2).
        restarted = ServerHarness(make_config(self.directory, active=1))
        try:
            self.assertEqual(restarted.server.ledger.active_version, 2)
            status, body = self._call(restarted, "GET", "/v1/keys")
            self.assertEqual(body, {"active_version": 2})
            status, body = self._call(restarted, "GET", "/v1/records/rec1", tenant="acme")
            self.assertEqual(body["plaintext"], "persist 内容")
            self.assertEqual(body["key_version"], 2)
            status, body = self._call(restarted, "POST", "/v1/records",
                                      {"id": "rec2", "plaintext": "new"}, tenant="acme")
            self.assertEqual(body["key_version"], 2)
        finally:
            restarted.close()

    def test_old_unreferenced_key_can_be_removed(self):
        self.create("rec", "payload")
        self.request("POST", "/v1/keys/rotate", {"version": 3})
        self.harness.close()
        # Only version 3 remains in the keyring file; records all reference 3.
        restarted = ServerHarness(make_config(self.directory, active=3, versions=(3,)))
        try:
            status, body = self._call(restarted, "GET", "/v1/records/rec", tenant="acme")
            self.assertEqual((status, body["plaintext"]), (200, "payload"))
        finally:
            restarted.close()

    def test_database_holds_no_plaintext_or_key_material(self):
        secret = "独一无二的秘密载荷-7f3d9c1e"
        self.create("doc", secret)
        self.request("POST", "/v1/keys/rotate", {"version": 2})
        self.harness.close()
        # Scan the main file plus WAL/SHM, where recently written pages may live.
        blobs = []
        for suffix in ("", "-wal", "-shm"):
            path = self.directory / ("ledger.sqlite3" + suffix)
            if path.exists():
                blobs.append(path.read_bytes())
        database_bytes = b"".join(blobs)
        self.assertNotIn(secret.encode("utf-8"), database_bytes)
        for material in KEY_MATERIAL.values():
            self.assertNotIn(material, database_bytes)

    def test_records_table_public_shape(self):
        self.create("doc", "x")
        raw = connect(self.directory / "ledger.sqlite3")
        columns = {r[1]: r[2] for r in raw.execute("PRAGMA table_info(records)")}
        raw.close()
        self.assertEqual(columns["tenant"], "TEXT")
        self.assertEqual(columns["id"], "TEXT")
        self.assertEqual(columns["key_version"], "INTEGER")
        self.assertEqual(columns["nonce"], "BLOB")
        self.assertEqual(columns["ciphertext"], "BLOB")
        self.assertEqual(columns["wrap_nonce"], "BLOB")
        self.assertEqual(columns["wrapped_key"], "BLOB")
        raw = connect(self.directory / "ledger.sqlite3")
        try:
            row = raw.execute(
                "SELECT nonce, ciphertext, wrap_nonce, wrapped_key FROM records"
            ).fetchone()
            self.assertEqual([len(row[i]) for i in range(4)], [12, 1 + 16, 12, 32 + 16])
        finally:
            raw.close()

    # -- concurrency -------------------------------------------------------

    def test_concurrent_creates_same_id_single_winner(self):
        barrier = threading.Barrier(8)

        def create():
            barrier.wait()
            create_result.append(self.create("race", "same payload")[0])

        create_result = []
        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(create_result).count(201), 1)
        self.assertEqual(sorted(create_result).count(409), 7)

    def test_concurrent_rotation_same_version_one_real_one_noop(self):
        for i in range(4):
            self.create(f"rec{i}", f"p{i}")
        barrier = threading.Barrier(2)
        results = []

        def rotate():
            barrier.wait()
            results.append(self.request("POST", "/v1/keys/rotate", {"version": 2}))

        threads = [threading.Thread(target=rotate) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(body["rewrapped"] for _, body in results), [0, 4])
        self.assertTrue(all(status == 200 for status, _ in results))

    def test_creates_concurrent_with_rotation_all_final_version(self):
        for i in range(5):
            self.create(f"old{i}", f"old {i}")
        barrier = threading.Barrier(6)
        failures = []

        def make_new(index):
            barrier.wait()
            status, _ = self.create(f"new{index}", f"new {index}")
            if status != 201:
                failures.append(status)

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2})
            if status != 200:
                failures.append((status, body))

        threads = [threading.Thread(target=make_new, args=(i,)) for i in range(5)]
        threads.append(threading.Thread(target=rotate))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(self.request("GET", "/v1/keys")[1], {"active_version": 2})
        raw = connect(self.directory / "ledger.sqlite3")
        versions = {r[0] for r in raw.execute("SELECT DISTINCT key_version FROM records")}
        count = raw.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        raw.close()
        self.assertEqual(versions, {2})
        self.assertEqual(count, 10)
        for record_id in [f"old{i}" for i in range(5)] + [f"new{i}" for i in range(5)]:
            self.assertEqual(self.read(record_id)[0], 200)

    # -- helpers -----------------------------------------------------------

    def _call(self, harness, method, path, body=None, tenant=None):
        headers = {}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        data = json.dumps(body).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(harness.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())


class BatchRecordProtocolTests(unittest.TestCase):
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

    def batch(self, records, tenant="acme"):
        return self.request("POST", "/v1/records/batch", {"records": records}, tenant=tenant)

    def read(self, record_id, tenant="acme"):
        return self.request("GET", f"/v1/records/{record_id}", None, tenant=tenant)

    def entry(self, index, plaintext):
        return {"id": f"invoice_{index}", "plaintext": plaintext}

    # -- success -----------------------------------------------------------

    def test_batch_creates_and_reports_ordered_ids(self):
        status, body = self.batch([self.entry(1, "one"), self.entry(2, "two 内容")])
        self.assertEqual(
            (status, body),
            (201, {"key_version": 1, "created": ["invoice_1", "invoice_2"]}),
        )
        self.assertEqual(self.read("invoice_1")[1]["plaintext"], "one")
        self.assertEqual(self.read("invoice_2")[1],
                         {"id": "invoice_2", "plaintext": "two 内容", "key_version": 1})

    def test_batch_preserves_empty_chinese_emoji_newline(self):
        cases = ("", "中文内容", "emoji 😀🎉 mixed", "line1\nline2\r\n\t结束", "😀" * 100)
        records = [{"id": f"r_{index}", "plaintext": value} for index, value in enumerate(cases)]
        self.assertEqual(self.batch(records), (201, {"key_version": 1, "created": [r["id"] for r in records]}))
        for index, value in enumerate(cases):
            self.assertEqual(self.read(f"r_{index}")[1]["plaintext"], value)

    def test_batch_uses_independent_data_keys_and_nonces(self):
        records = [{"id": "a", "plaintext": "same plaintext"}, {"id": "b", "plaintext": "same plaintext"}]
        self.assertEqual(self.batch(records)[0], 201)
        raw = connect(self.directory / "ledger.sqlite3")
        rows = {r[0]: tuple(r[1:]) for r in raw.execute(
            "SELECT id, nonce, ciphertext, wrap_nonce, wrapped_key FROM records ORDER BY id"
        )}
        raw.close()
        # nonce=12, ciphertext=plaintext+tag (14+16), wrap_nonce=12, wrapped_key=48.
        self.assertEqual([len(rows["a"][i]) for i in range(4)], [12, 30, 12, 48])
        for column in range(4):
            self.assertNotEqual(rows["a"][column], rows["b"][column])

    def test_batch_extra_fields_are_ignored(self):
        status, body = self.batch([{"id": "x", "plaintext": "p", "note": "ignored", "n": 1}])
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["x"]}))

    def test_batch_size_boundaries_accept_100_reject_101(self):
        exact = [{"id": f"id_{index}", "plaintext": "p"} for index in range(100)]
        self.assertEqual(self.batch(exact)[0], 201)
        too_many = [{"id": f"other_{index}", "plaintext": "p"} for index in range(101)]
        self.assertEqual(self.batch(too_many), (400, {"error": "invalid_request"}))

    def test_batch_plaintext_byte_limit_per_item(self):
        exact = [{"id": "ok", "plaintext": "a" * 65536}]
        self.assertEqual(self.batch(exact)[0], 201)
        too_long = [{"id": "no", "plaintext": "a" * 65537}]
        self.assertEqual(self.batch(too_long), (400, {"error": "invalid_request"}))
        multibyte = [{"id": "mb_ok", "plaintext": "中" * 21845 + "a"},
                     {"id": "mb_no", "plaintext": "中" * 21846}]
        self.assertEqual(self.batch(multibyte), (400, {"error": "invalid_request"}))

    # -- validation --------------------------------------------------------

    def test_batch_invalid_requests(self):
        good = {"id": "ok", "plaintext": "x"}
        cases = [
            ({"records": [good]}, None),
            ({"records": [good]}, "bad tenant!"),
            ({}, "acme"),
            ({"records": "nope"}, "acme"),
            ({"records": []}, "acme"),
            ({"records": [{"id": "x"}]}, "acme"),
            ({"records": [{"plaintext": "x"}]}, "acme"),
            ({"records": [{"id": 7, "plaintext": "x"}]}, "acme"),
            ({"records": [{"id": "", "plaintext": "x"}]}, "acme"),
            ({"records": [{"id": "x" * 65, "plaintext": "x"}]}, "acme"),
            ({"records": [{"id": "ok", "plaintext": 42}]}, "acme"),
            ({"records": [{"id": "ok", "plaintext": None}]}, "acme"),
            ({"records": ["nope"]}, "acme"),
            ({"records": [good, "nope"]}, "acme"),
            ("nope", "acme"),
            ('{"records":[', "acme"),
            ([good], "acme"),
        ]
        for body, tenant in cases:
            with self.subTest(body=body, tenant=tenant):
                self.assertEqual(self.request("POST", "/v1/records/batch", body, tenant),
                                 (400, {"error": "invalid_request"}))

    def test_batch_64_char_identifier_accepted(self):
        status, body = self.batch([{"id": "a" * 64, "plaintext": "x"}])
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["a" * 64]}))

    # -- conflicts ---------------------------------------------------------

    def test_batch_duplicate_id_in_same_batch_is_conflict_without_writes(self):
        records = [{"id": "dup", "plaintext": "first"}, {"id": "dup", "plaintext": "second"}]
        self.assertEqual(self.batch(records), (409, {"error": "conflict"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        raw.close()

    def test_batch_existing_id_is_conflict_and_writes_nothing(self):
        self.request("POST", "/v1/records", {"id": "old", "plaintext": "kept"})
        records = [{"id": "new", "plaintext": "n"}, {"id": "old", "plaintext": "overwrite"}]
        self.assertEqual(self.batch(records), (409, {"error": "conflict"}))
        self.assertEqual(self.read("old")[1]["plaintext"], "kept")
        self.assertEqual(self.read("new")[0], 404)

    def test_batch_same_id_across_tenants_is_independent(self):
        status, body = self.batch([{"id": "shared", "plaintext": "tenant-a"}], tenant="alpha")
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["shared"]}))
        status, body = self.batch([{"id": "shared", "plaintext": "tenant-b"}], tenant="beta")
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["shared"]}))
        self.assertEqual(self.read("shared", tenant="alpha")[1]["plaintext"], "tenant-a")
        self.assertEqual(self.read("shared", tenant="beta")[1]["plaintext"], "tenant-b")

    def test_batch_conflict_does_not_affect_other_tenant(self):
        self.request("POST", "/v1/records", {"id": "only", "plaintext": "a"}, tenant="alpha")
        status, body = self.batch([{"id": "only", "plaintext": "b"}], tenant="beta")
        self.assertEqual((status, body), (201, {"key_version": 1, "created": ["only"]}))

    # -- storage failure ---------------------------------------------------

    def test_batch_storage_failure_is_503_without_partial_commit(self):
        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("CREATE TRIGGER block_records_insert BEFORE INSERT ON records "
                        "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END")
        raw.close()

        records = [{"id": f"r{index}", "plaintext": f"p{index}"} for index in range(5)]
        self.assertEqual(self.batch(records), (503, {"error": "storage_error"}))
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        raw.close()

        raw = connect(self.directory / "ledger.sqlite3")
        with raw:
            raw.execute("DROP TRIGGER block_records_insert")
        raw.close()
        self.assertEqual(self.batch([{"id": "after", "plaintext": "works"}])[0], 201)
        self.assertEqual(self.read("after")[1]["plaintext"], "works")

    # -- concurrency -------------------------------------------------------

    def test_concurrent_batches_same_ids_single_winner(self):
        barrier = threading.Barrier(8)
        results = []

        def create_batch():
            barrier.wait()
            records = [{"id": f"race_{offset}", "plaintext": "p"} for offset in range(3)]
            results.append(self.batch(records)[0])

        threads = [threading.Thread(target=create_batch) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(409), 7)
        raw = connect(self.directory / "ledger.sqlite3")
        self.assertEqual(raw.execute("SELECT COUNT(*) FROM records").fetchone()[0], 3)
        raw.close()

    def test_batch_and_single_create_same_id_single_winner(self):
        barrier = threading.Barrier(4)
        results = []

        def batch_create():
            barrier.wait()
            results.append(self.batch([{"id": "x", "plaintext": "batch"}])[0])

        def single_create():
            barrier.wait()
            payload = json.dumps({"id": "x", "plaintext": "single"}).encode("utf-8")
            request = urllib.request.Request(
                self.harness.base + "/v1/records", data=payload,
                headers={"X-Tenant-ID": "acme", "Content-Type": "application/json"}, method="POST",
            )
            try:
                with urllib.request.urlopen(request) as response:
                    results.append(response.status)
            except urllib.error.HTTPError as exc:
                with exc:
                    exc.read()
                    results.append(exc.code)

        threads = [threading.Thread(target=batch_create) for _ in range(2)]
        threads += [threading.Thread(target=single_create) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(409), 3)

    def test_batches_concurrent_with_rotation_use_final_version(self):
        self.request("POST", "/v1/records", {"id": "old0", "plaintext": "old"})
        barrier = threading.Barrier(4)
        failures = []

        def batch_create(index):
            barrier.wait()
            records = [{"id": f"new_{index}_{offset}", "plaintext": f"n{offset}"} for offset in range(3)]
            status, body = self.batch(records)
            if status != 201:
                failures.append((status, body))

        def rotate():
            barrier.wait()
            status, body = self.request("POST", "/v1/keys/rotate", {"version": 2}, None)
            if status != 200:
                failures.append((status, body))

        threads = [threading.Thread(target=batch_create, args=(i,)) for i in range(3)]
        threads.append(threading.Thread(target=rotate))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(self.request("GET", "/v1/keys", None), (200, {"active_version": 2}))
        raw = connect(self.directory / "ledger.sqlite3")
        versions = {r[0] for r in raw.execute("SELECT DISTINCT key_version FROM records")}
        count = raw.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        raw.close()
        self.assertEqual(versions, {2})
        self.assertEqual(count, 10)
        for index in range(3):
            for offset in range(3):
                self.assertEqual(self.read(f"new_{index}_{offset}")[1]["key_version"], 2)
        self.assertEqual(self.read("old0")[1]["key_version"], 2)


if __name__ == "__main__":
    unittest.main()
