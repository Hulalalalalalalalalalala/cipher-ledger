"""Contract tests for GET /v1/encrypted-records/batches.

The collection endpoint lists the summaries (batch_id, count, created_at) of a
tenant's committed sealed batches in batch_id ASCII order, paginated from a
snapshot fixed by the first cursor-less request. Success shape, snapshot
semantics, opaque cursors (restart/rotation stable, tenant bound), error
precedence and summary-only integrity checks are exercised here; most tampering
is performed directly on the SQLite file.
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
LIST_PATH = "/v1/encrypted-records/batches"


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


def sealed_record(record_id, algorithm="AES-256-GCM"):
    wrapped_len = 48 if algorithm == "AES-256-GCM" else 32
    return {
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


class EncryptedBatchListTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)
        # Every ingested record needs a tenant-unique id, including across
        # batches, so generate them from one monotonic counter.
        self._record_seq = 0

    def request(self, method, path, body=None, tenant="acme", headers=None):
        sent_headers = dict(headers or {})
        if tenant is not None:
            sent_headers["X-Tenant-ID"] = tenant
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            sent_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.harness.base + path, data=data, headers=sent_headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def ingest(self, count, tenant="acme", prefix="r", idempotency_key=None):
        start = self._record_seq
        self._record_seq += count
        records = [sealed_record(f"{prefix}{start + i:06d}") for i in range(count)]
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self.request(
            "POST", INGEST_PATH, {"records": records}, tenant=tenant, headers=headers
        )

    def ingest_named(self, record_ids, tenant="acme"):
        return self.request(
            "POST",
            INGEST_PATH,
            {"records": [sealed_record(record_id) for record_id in record_ids]},
            tenant=tenant,
        )

    def list_batches(self, query="", tenant="acme"):
        path = LIST_PATH if not query else LIST_PATH + "?" + query
        return self.request("GET", path, None, tenant=tenant)

    def get_batch(self, batch_id, tenant="acme"):
        return self.request(
            "GET", f"/v1/encrypted-records/batches/{batch_id}", None, tenant=tenant
        )

    def walk(self, first_query="", tenant="acme"):
        """Follow next_cursor until exhausted; return (items, raw_pages).

        A ``limit`` given on the first request is repeated on every
        continuation so the walk exercises the same page size throughout.
        """
        limit_segment = ""
        for segment in first_query.split("&") if first_query else ():
            if segment.startswith("limit="):
                limit_segment = segment
        status, page = self.list_batches(first_query, tenant=tenant)
        self.assertEqual(status, 200)
        pages = [page]
        items = list(page["items"])
        cursor = page.get("next_cursor")
        while cursor:
            query = f"cursor={cursor}" + (f"&{limit_segment}" if limit_segment else "")
            status, page = self.list_batches(query, tenant=tenant)
            self.assertEqual(status, 200)
            pages.append(page)
            items.extend(page["items"])
            cursor = page.get("next_cursor")
        return items, pages

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def tamper(self, sql, params=()):
        raw = self.db()
        try:
            with raw:
                raw.execute(sql, params)
        finally:
            raw.close()

    # -- success -----------------------------------------------------------

    def test_empty_tenant_returns_empty_object(self):
        self.assertEqual(self.list_batches(), (200, {"items": []}))

    def test_single_page_shape_and_values_match_batch_read(self):
        batch_id = self.ingest_named(["zeta", "alpha", "mid"])[1]["batch_id"]
        status, body = self.list_batches()
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"items"})
        self.assertEqual(len(body["items"]), 1)
        item = body["items"][0]
        self.assertEqual(set(item), {"batch_id", "count", "created_at"})
        read_status, read_body = self.get_batch(batch_id)
        self.assertEqual(read_status, 200)
        self.assertEqual(item["batch_id"], batch_id)
        self.assertEqual(item["count"], read_body["count"])
        self.assertEqual(item["created_at"], read_body["created_at"])

    def test_items_sorted_by_batch_id_ascii(self):
        ids = []
        for _ in range(7):
            batch_id = self.ingest(1)[1]["batch_id"]
            ids.append(batch_id)
        status, body = self.list_batches("limit=100")
        self.assertEqual(status, 200)
        returned = [item["batch_id"] for item in body["items"]]
        self.assertEqual(returned, sorted(ids))
        # Explicitly the BINARY/ASCII order SQLite uses.
        self.assertEqual(returned, sorted(ids, key=lambda value: value.encode("ascii")))
        self.assertNotIn("next_cursor", body)

    def test_default_limit_is_fifty(self):
        for _ in range(51):
            self.ingest(1)
        status, first = self.list_batches()
        self.assertEqual(status, 200)
        self.assertEqual(len(first["items"]), 50)
        self.assertIn("next_cursor", first)
        status, second = self.list_batches(f"cursor={first['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual(len(second["items"]), 1)
        self.assertNotIn("next_cursor", second)

    def test_pagination_visits_every_batch_once(self):
        ids = [self.ingest(1, prefix=f"b{i:03d}")[1]["batch_id"] for i in range(25)]
        items, pages = self.walk("limit=10")
        self.assertEqual([len(page["items"]) for page in pages], [10, 10, 5])
        walked = [item["batch_id"] for item in items]
        self.assertEqual(walked, sorted(ids))
        self.assertEqual(len(walked), len(set(walked)))
        for item in items:
            self.assertEqual(item["count"], 1)

    def test_limit_change_is_allowed_on_continuation(self):
        for _ in range(10):
            self.ingest(1)
        status, first = self.list_batches("limit=2")
        self.assertEqual(len(first["items"]), 2)
        cursor = first["next_cursor"]
        status, second = self.list_batches(f"limit=3&cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual(len(second["items"]), 3)
        cursor = second["next_cursor"]
        status, third = self.list_batches(f"cursor={cursor}&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(len(third["items"]), 5)
        self.assertNotIn("next_cursor", third)

    def test_same_cursor_and_limit_replays_same_page(self):
        for _ in range(6):
            self.ingest(1)
        first = self.list_batches("limit=2")[1]
        cursor = first["next_cursor"]
        page_a = self.list_batches(f"limit=2&cursor={cursor}")[1]
        page_b = self.list_batches(f"limit=2&cursor={cursor}")[1]
        self.assertEqual(page_a, page_b)
        self.assertEqual(len(page_a["items"]), 2)

    def test_existing_batches_listed_after_restart_without_rewrite(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)
        status, body = self.list_batches()
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], sorted(ids))

    def test_other_tenants_batches_are_invisible(self):
        alpha = self.ingest(2, tenant="alpha", prefix="a")[1]["batch_id"]
        beta = self.ingest(1, tenant="beta", prefix="b")[1]["batch_id"]
        self.assertEqual(
            [item["batch_id"] for item in self.list_batches(tenant="alpha")[1]["items"]],
            [alpha],
        )
        self.assertEqual(
            [item["batch_id"] for item in self.list_batches(tenant="beta")[1]["items"]],
            [beta],
        )
        self.assertEqual(self.list_batches(tenant="gamma"), (200, {"items": []}))

    def test_server_side_encrypted_records_never_appear(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        for record_id in ("p1", "p2"):
            self.assertEqual(
                self.request(
                    "POST", "/v1/records", {"id": record_id, "plaintext": "secret"}
                )[0],
                201,
            )
        status, body = self.list_batches()
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], [batch_id])

    # -- snapshot semantics ------------------------------------------------

    def test_new_commits_stay_invisible_until_fresh_listing(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(4)]
        first = self.list_batches("limit=3")[1]
        self.assertEqual([item["batch_id"] for item in first["items"]], sorted(ids)[:3])
        cursor = first["next_cursor"]

        late = [self.ingest(1, prefix="late")[1]["batch_id"] for _ in range(3)]

        second = self.list_batches(f"cursor={cursor}")[1]
        self.assertEqual([item["batch_id"] for item in second["items"]], [sorted(ids)[3]])
        self.assertNotIn("next_cursor", second)

        # The frozen walk still does not see the new batches on replay.
        replay = self.list_batches(f"cursor={cursor}")[1]
        self.assertEqual(replay, second)

        # A fresh cursor-less listing captures a new state with all batches.
        items, _ = self.walk("limit=2")
        self.assertEqual(
            [item["batch_id"] for item in items], sorted(ids + late)
        )

    def test_cursor_survives_restart_and_rotation_with_same_digest(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(6)]
        first = self.list_batches("limit=2")[1]
        cursor = first["next_cursor"]

        # Record-key rotation must neither change the digest nor invalidate it.
        self.assertEqual(
            self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200
        )
        page = self.list_batches(f"limit=2&cursor={cursor}")[1]
        self.assertEqual([item["batch_id"] for item in page["items"]], sorted(ids)[2:4])
        next_cursor = page["next_cursor"]

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory, active=2))
        self.addCleanup(self.harness.close)
        # The very cursor issued before the restart still resolves.
        status, body = self.list_batches(f"limit=2&cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], sorted(ids)[2:4])
        # ...and the walk completes without gaps.
        tail = self.list_batches(f"limit=2&cursor={next_cursor}")[1]
        self.assertEqual([item["batch_id"] for item in tail["items"]], sorted(ids)[4:6])
        self.assertNotIn("next_cursor", tail)

    def test_failed_write_adds_no_listing_entry(self):
        valid = [sealed_record("ok")]
        # In-batch duplicate id -> 400, nothing committed.
        status, _ = self.request(
            "POST",
            INGEST_PATH,
            {"records": [sealed_record("dup"), sealed_record("dup")]},
        )
        self.assertEqual(status, 400)
        batch_id = self.request("POST", INGEST_PATH, {"records": valid})[1]["batch_id"]
        self.assertEqual(
            [item["batch_id"] for item in self.list_batches()[1]["items"]],
            [batch_id],
        )

    def test_idempotent_replay_adds_no_listing_entry(self):
        payload = {"records": [sealed_record("idem")]}
        first_status, first_body = self.request(
            "POST", INGEST_PATH, payload, headers={"Idempotency-Key": "key-1"}
        )
        self.assertEqual(first_status, 201)
        replay_status, replay_body = self.request(
            "POST", INGEST_PATH, payload, headers={"Idempotency-Key": "key-1"}
        )
        self.assertEqual(replay_status, 200)
        self.assertEqual(replay_body["batch_id"], first_body["batch_id"])
        status, body = self.list_batches()
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]],
                         [first_body["batch_id"]])

    def test_listing_is_read_only_and_single_page_persists_nothing(self):
        self.ingest(1)
        for _ in range(3):
            self.assertEqual(self.list_batches()[0], 200)
        raw = self.db()
        try:
            # A single-page listing retains no snapshot state at all.
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_batch_list_snapshots")
                .fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_batch_list_entries")
                .fetchone()[0],
                0,
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 1
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                1,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
                0,
            )
        finally:
            raw.close()
        # Walking a multi-page listing adds only snapshot bookkeeping rows; the
        # protocol tables gain just the four new batches.
        for _ in range(4):
            self.ingest(1)
        self.walk("limit=2")
        raw = self.db()
        try:
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 5
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0], 5
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                5,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
                0,
            )
        finally:
            raw.close()

    # -- request validation and error precedence ---------------------------

    def test_missing_or_invalid_tenant_is_forbidden_first(self):
        for query in ("", "limit=1", "limit=0", "cursor=x", "limit=1&cursor=y"):
            with self.subTest(query=query):
                for tenant in (None, "bad tenant!", "a/b"):
                    status, body = self.list_batches(query, tenant=tenant)
                    self.assertEqual(
                        (status, body), (403, {"error": "TENANT_RECORD_FORBIDDEN"})
                    )

    def test_limit_boundaries(self):
        for _ in range(2):
            self.ingest(1)
        for value in ("1", "01", "007", "100"):
            self.assertEqual(self.list_batches(f"limit={value}")[0], 200, value)
        for value in (
            "0", "101", "1000", "-1", "1.5", "0x1", "%201", "1%20",
            "", "a", "%EF%BC%95", "true",
        ):
            status, body = self.list_batches(f"limit={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_empty_or_invalid_cursor_is_invalid_request(self):
        for _ in range(3):
            self.ingest(1)
        valid = self.list_batches("limit=1")[1]["next_cursor"]
        body, tag = valid.split(".", 1)

        def flip_tag(encoded_tag: str) -> str:
            raw = bytearray(
                base64.urlsafe_b64decode(encoded_tag + "=" * (-len(encoded_tag) % 4))
            )
            raw[0] ^= 0x80
            return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

        def flip_body(encoded_body: str) -> str:
            # Flip a guaranteed-significant payload byte; the HMAC over the
            # body then mismatches regardless of base64 trailing-bit luck.
            raw = bytearray(
                base64.urlsafe_b64decode(encoded_body + "=" * (-len(encoded_body) % 4))
            )
            raw[0] ^= 0x01
            return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

        cases = [
            "",
            "not-a-cursor",
            "a.b.c",
            body + "." + flip_tag(tag),
            "YWJj." + tag,
            flip_body(body) + "." + tag,
        ]
        for value in cases:
            status, payload = self.list_batches(f"cursor={value}")
            self.assertEqual((status, payload), (400, {"error": "invalid_request"}), value)

    def test_cursor_from_other_tenant_is_rejected(self):
        for _ in range(3):
            self.ingest(1, tenant="alpha")
        cursor = self.list_batches("limit=1", tenant="alpha")[1]["next_cursor"]
        self.assertEqual(
            self.list_batches(f"cursor={cursor}", tenant="beta"),
            (400, {"error": "invalid_request"}),
        )

    def test_duplicate_limit_or_cursor_is_invalid_request(self):
        for _ in range(2):
            self.ingest(1)
        self.assertEqual(
            self.list_batches("limit=1&limit=1"), (400, {"error": "invalid_request"})
        )
        self.assertEqual(
            self.list_batches("cursor=a&cursor=b"), (400, {"error": "invalid_request"})
        )

    def test_unknown_query_parameters_are_ignored(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        status, body = self.list_batches("foo=bar&baz=&order=desc&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], [batch_id])

    # -- storage and integrity failures ------------------------------------

    def test_sqlite_read_failure_is_503(self):
        self.ingest(1)
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.list_batches(), (503, {"error": "storage_error"}))

    def test_storage_failure_on_continuation_is_503(self):
        for _ in range(4):
            self.ingest(1)
        cursor = self.list_batches("limit=2")[1]["next_cursor"]
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batch_list_entries")
        raw.close()
        self.assertEqual(
            self.list_batches(f"cursor={cursor}"), (503, {"error": "storage_error"})
        )

    def test_corrupt_summary_in_returned_page_is_422(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        for value in (0, 101, "two"):
            self.tamper(
                "UPDATE encrypted_batches SET record_count=? WHERE batch_id=?",
                (value, batch_id),
            )
            with self.subTest(value=value):
                self.assertEqual(
                    self.list_batches(), (422, {"error": "integrity_error"})
                )
        # created_at stored as a BLOB keeps blob affinity and returns bytes.
        self.tamper(
            "UPDATE encrypted_batches SET record_count=1, created_at=? WHERE batch_id=?",
            (b"not-a-string", batch_id),
        )
        self.assertEqual(self.list_batches(), (422, {"error": "integrity_error"}))
        self.tamper(
            "UPDATE encrypted_batches SET created_at='2026-01-01T00:00:00+00:00' "
            "WHERE batch_id=?",
            (batch_id,),
        )
        self.assertEqual(self.list_batches()[0], 200)

    def test_malformed_batch_id_in_page_is_422(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        self.tamper(
            "UPDATE encrypted_batches SET batch_id=? WHERE batch_id=?",
            ("batch_" + "z" * 32, batch_id),
        )
        self.assertEqual(self.list_batches(), (422, {"error": "integrity_error"}))

    def test_corrupt_summary_beyond_returned_page_does_not_spoil_page(self):
        ids = [self.ingest(1, prefix=f"c{i}")[1]["batch_id"] for i in range(4)]
        ordered = sorted(ids)
        # The last-sorted batch is corrupt; earlier pages must still be served.
        self.tamper(
            "UPDATE encrypted_batches SET record_count=0 WHERE batch_id=?",
            (ordered[-1],),
        )
        status, first = self.list_batches("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["batch_id"] for item in first["items"]], ordered[:2]
        )
        cursor = first["next_cursor"]
        # The continuation snapshot freezes the corrupt value: page 2 422s.
        self.assertEqual(
            self.list_batches(f"cursor={cursor}"),
            (422, {"error": "integrity_error"}),
        )
        # A single-page request that includes the corrupt batch also 422s.
        self.assertEqual(self.list_batches("limit=100"),
                         (422, {"error": "integrity_error"}))

    # -- concurrency -------------------------------------------------------

    def test_concurrent_commits_never_show_partial_batches(self):
        barrier = threading.Barrier(4)
        failures = []
        lock = threading.Lock()
        committed = []
        committed_lock = threading.Lock()

        def writer(index):
            barrier.wait()
            for round_index in range(8):
                status, body = self.ingest(
                    2, prefix=f"w{index}_{round_index}_"
                )
                if status != 201:
                    with lock:
                        failures.append(("write", status, body))
                    continue
                batch_id = body["batch_id"]
                with committed_lock:
                    committed.append(batch_id)
                # The just-committed batch reads whole immediately.
                read_status, read_body = self.get_batch(batch_id)
                if read_status != 200 or read_body["count"] != 2:
                    with lock:
                        failures.append(("readown", read_status, read_body))

        def lister():
            barrier.wait()
            for _ in range(40):
                items, pages = self.walk("limit=3")
                ids = [item["batch_id"] for item in items]
                if len(ids) != len(set(ids)):
                    with lock:
                        failures.append(("duplicate", ids))
                    continue
                if ids != sorted(ids):
                    with lock:
                        failures.append(("order", ids))
                    continue
                for item in items:
                    if not (1 <= item["count"] <= 100) or not isinstance(
                        item["created_at"], str
                    ):
                        with lock:
                            failures.append(("shape", item))
                        continue
                    # The summary of every listed batch must agree with the
                    # whole-batch read; a partially committed batch could not.
                    status, body = self.get_batch(item["batch_id"])
                    if (
                        status != 200
                        or body["count"] != item["count"]
                        or body["created_at"] != item["created_at"]
                        or len(body["records"]) != item["count"]
                    ):
                        with lock:
                            failures.append(("mismatch", item, status, body))
                # A frozen walk must be self-consistent across its pages.
                if any(set(page) - {"items", "next_cursor"} for page in pages):
                    with lock:
                        failures.append(("page-shape", pages))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads.append(threading.Thread(target=lister))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        # After all writers finish, a fresh walk lists exactly every commit.
        items, _ = self.walk("limit=7")
        self.assertEqual(
            [item["batch_id"] for item in items], sorted(committed)
        )


if __name__ == "__main__":
    unittest.main()
