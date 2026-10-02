"""Contract tests for GET /v1/encrypted-records/batches.

The endpoint lists the summary shapes (batch_id/count/created_at) of sealed
batches committed by the sealed-write ingress. Success shape and ordering,
frozen-snapshot pagination with restart-proof opaque cursors, error
precedence, per-page summary integrity checks, and serial visibility under
concurrent commits are all exercised here; tampering is performed directly on
the SQLite file.
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

    def request(self, method, path, body=None, tenant="acme", headers=None):
        sent_headers = {}
        if tenant is not None:
            sent_headers["X-Tenant-ID"] = tenant
        if headers:
            sent_headers.update(headers)
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

    def list_batches(self, query="", tenant="acme"):
        path = LIST_PATH if not query else LIST_PATH + "?" + query
        return self.request("GET", path, tenant=tenant)

    def ingest(self, count=1, tenant="acme", key=None, records=None):
        if records is None:
            records = [
                sealed_record(f"{tenant}-{os.urandom(8).hex()}-{i}") for i in range(count)
            ]
        headers = {"Idempotency-Key": key} if key is not None else None
        return self.request(
            "POST", INGEST_PATH, {"records": records}, tenant=tenant, headers=headers
        )

    def get_batch(self, batch_id, tenant="acme"):
        return self.request("GET", f"{LIST_PATH}/{batch_id}", tenant=tenant)

    def walk(self, first_query="", tenant="acme"):
        """Page through a whole listing; return (items, raw_pages)."""
        status, body = self.list_batches(first_query, tenant=tenant)
        self.assertEqual(status, 200)
        pages = [body]
        items = list(body["items"])
        cursor = body.get("next_cursor")
        # Keep the first page's page size while following the chain.
        limit_suffix = "&" + first_query if first_query.startswith("limit=") else ""
        while cursor:
            status, page = self.list_batches(f"cursor={cursor}{limit_suffix}", tenant=tenant)
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

    # -- success shape and ordering ----------------------------------------

    def test_empty_tenant_returns_empty_page_without_cursor(self):
        self.assertEqual(self.list_batches(), (200, {"items": []}))

    def test_items_sorted_ascii_by_batch_id_with_summary_shape_only(self):
        batch_ids = [self.ingest(1)[1]["batch_id"] for _ in range(8)]
        status, body = self.list_batches("limit=100")
        self.assertEqual(status, 200)
        self.assertNotIn("next_cursor", body)
        self.assertEqual(set(body), {"items"})
        returned = [item["batch_id"] for item in body["items"]]
        self.assertEqual(returned, sorted(batch_ids))
        # Every item carries exactly the three summary fields.
        for item in body["items"]:
            self.assertEqual(set(item), {"batch_id", "count", "created_at"})

    def test_summary_values_match_the_whole_batch_read(self):
        counts = {}
        for size in (1, 3, 2):
            batch_id = self.ingest(size)[1]["batch_id"]
            counts[batch_id] = size
        _, body = self.list_batches("limit=100")
        for item in body["items"]:
            status, full = self.get_batch(item["batch_id"])
            self.assertEqual(status, 200)
            self.assertEqual(item["batch_id"], full["batch_id"])
            self.assertEqual(item["count"], full["count"])
            self.assertEqual(item["count"], counts[item["batch_id"]])
            self.assertEqual(item["created_at"], full["created_at"])

    def test_existing_batches_are_listed_without_rewrite(self):
        batch_id = self.ingest(2)[1]["batch_id"]
        raw = self.db()
        try:
            before = raw.execute(
                "SELECT batch_id, tenant, record_count, created_at "
                "FROM encrypted_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone()
            before = tuple(before)
        finally:
            raw.close()
        self.assertEqual(self.list_batches()[0], 200)
        raw = self.db()
        try:
            after = tuple(raw.execute(
                "SELECT batch_id, tenant, record_count, created_at "
                "FROM encrypted_batches WHERE batch_id=?",
                (batch_id,),
            ).fetchone())
        finally:
            raw.close()
        self.assertEqual(after, before)

    def test_other_tenant_and_server_side_records_are_invisible(self):
        alpha = self.ingest(2, tenant="alpha")[1]["batch_id"]
        beta = self.ingest(1, tenant="beta")[1]["batch_id"]
        # Server-side encrypted records live in a different table and must not
        # appear as sealed batches for either tenant.
        self.assertEqual(
            self.request("POST", "/v1/records", {"id": "p1", "plaintext": "x"},
                         tenant="alpha")[0],
            201,
        )
        alpha_items, _ = self.walk(tenant="alpha")
        beta_items, _ = self.walk(tenant="beta")
        self.assertEqual([item["batch_id"] for item in alpha_items], [alpha])
        self.assertEqual([item["batch_id"] for item in beta_items], [beta])
        # A tenant with no sealed batches at all sees the empty envelope.
        self.assertEqual(self.list_batches(tenant="ghost"), (200, {"items": []}))

    # -- pagination ---------------------------------------------------------

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

    def test_pagination_walks_every_batch_once_without_gaps(self):
        batch_ids = [self.ingest(1)[1]["batch_id"] for _ in range(125)]
        items, pages = self.walk("limit=20")
        self.assertEqual([len(page["items"]) for page in pages],
                         [20, 20, 20, 20, 20, 20, 5])
        seen = [item["batch_id"] for item in items]
        self.assertEqual(seen, sorted(batch_ids))
        self.assertEqual(len(seen), len(set(seen)))

    def test_page_size_equal_to_total_is_single_page(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        status, body = self.list_batches("limit=3")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], sorted(ids))
        self.assertNotIn("next_cursor", body)

    def test_next_cursor_appears_exactly_when_another_page_exists(self):
        for _ in range(3):
            self.ingest(1)
        status, first = self.list_batches("limit=2")
        self.assertEqual(len(first["items"]), 2)
        self.assertIn("next_cursor", first)
        status, last = self.list_batches(f"cursor={first['next_cursor']}&limit=2")
        self.assertEqual(len(last["items"]), 1)
        self.assertNotIn("next_cursor", last)

    def test_limit_boundaries_accepted_and_rejected(self):
        self.ingest(2)
        for value in ("1", "01", "007", "100"):
            self.assertEqual(self.list_batches(f"limit={value}")[0], 200, value)
        for value in ("0", "101", "1000", "-1", "1.5", "0x1", "%201", "1%20",
                      "", "a", "%EF%BC%95", "true"):
            status, body = self.list_batches(f"limit={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_duplicate_limit_or_cursor_is_rejected(self):
        for _ in range(4):
            self.ingest(1)
        cursor = self.list_batches("limit=1")[1]["next_cursor"]
        self.assertEqual(self.list_batches("limit=1&limit=1"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.list_batches(f"cursor={cursor}&cursor={cursor}"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.list_batches("limit=1&limit=2&cursor=x"),
                         (400, {"error": "invalid_request"}))

    def test_unknown_query_parameters_are_ignored(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        status, body = self.list_batches("foo=bar&baz=&limit=100&order=desc")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in body["items"]], [batch_id])

    # -- frozen snapshot semantics -----------------------------------------

    def test_snapshot_excludes_later_commits_until_fresh_listing(self):
        first_wave = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        status, page = self.list_batches("limit=2")
        self.assertEqual([item["batch_id"] for item in page["items"]], sorted(first_wave)[:2])
        cursor = page["next_cursor"]

        later = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        self.request("POST", "/v1/keys/rotate", {"version": 2})

        status, second = self.list_batches(f"cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in second["items"]],
                         sorted(first_wave)[2:])
        self.assertNotIn("next_cursor", second)

        # The same cursor is replayable and stays pinned to the old snapshot.
        status, replay = self.list_batches(f"cursor={cursor}")
        self.assertEqual([item["batch_id"] for item in replay["items"]],
                         sorted(first_wave)[2:])

        # A fresh cursorless listing observes the current complete state.
        items, _ = self.walk("limit=2")
        self.assertEqual(
            [item["batch_id"] for item in items], sorted(first_wave + later)
        )

    def test_limit_may_change_between_pages(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(5)]
        _, first = self.list_batches("limit=2")
        cursor = first["next_cursor"]
        # Continue with a much larger page size; the offset stays valid.
        status, rest = self.list_batches(f"cursor={cursor}&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in rest["items"]], sorted(ids)[2:])
        self.assertNotIn("next_cursor", rest)

    def test_same_cursor_and_limit_replays_the_same_page(self):
        for _ in range(4):
            self.ingest(1)
        cursor = self.list_batches("limit=2")[1]["next_cursor"]
        responses = [self.list_batches(f"cursor={cursor}&limit=2")[1] for _ in range(3)]
        for body in responses[1:]:
            self.assertEqual(body, responses[0])

    def test_failed_writes_and_idempotent_replays_add_no_listing_items(self):
        records = [sealed_record("dup-a"), sealed_record("dup-b")]
        self.assertEqual(self.ingest(records=records)[0], 201)
        # A keyless retry fails (ids exist) and creates no batch.
        self.assertEqual(self.ingest(records=records)[0], 400)
        # A keyed first write and its same-content replay share one batch.
        replay_records = [sealed_record("keyed-a")]
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 201)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)

        items, _ = self.walk("limit=1")
        self.assertEqual(len(items), 2)
        raw = self.db()
        try:
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 2
            )
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                3,
            )
            self.assertEqual(
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
                1,
            )
        finally:
            raw.close()

    # -- restart and key rotation ------------------------------------------

    def test_cursor_survives_restart_and_replays_identical_page(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(5)]
        status, first = self.list_batches("limit=2")
        self.assertEqual(status, 200)
        cursor = first["next_cursor"]
        # Capture page two before restart to compare the identical replay.
        status, second = self.list_batches(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        second_page = second["items"]

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        # The exact cursor from the old process still serves the same page.
        status, after = self.list_batches(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(after["items"], second_page)
        # ... and paging through completes the same frozen set without gaps.
        items, pages = self.walk_restarted("limit=2", first)
        self.assertEqual([item["batch_id"] for item in items], sorted(ids))
        # A fresh listing after restart works and needs no rewrite.
        self.assertEqual(
            [item["batch_id"] for item in self.list_batches("limit=100")[1]["items"]],
            sorted(ids),
        )

    def walk_restarted(self, first_query, first_page):
        body = first_page
        pages = [body]
        items = list(body["items"])
        cursor = body.get("next_cursor")
        while cursor:
            _, page = self.list_batches(f"cursor={cursor}&limit=2")
            pages.append(page)
            items.extend(page["items"])
            cursor = page.get("next_cursor")
        return items, pages

    def test_key_rotation_neither_changes_listing_nor_invalidates_cursor(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(4)]
        before = self.list_batches("limit=2")[1]
        cursor = before["next_cursor"]
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200)
        # Cursor and page digest are unchanged by rotation.
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=2")[1]["items"],
                         self.list_batches(f"cursor={cursor}&limit=2")[1]["items"])
        status, page = self.list_batches(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in page["items"]], sorted(ids)[2:])
        # Sealed batches are untouched by rotation and still listed wholesale.
        status, fresh = self.list_batches("limit=100")
        self.assertEqual([item["batch_id"] for item in fresh["items"]], sorted(ids))

    # -- request validation and error precedence ---------------------------

    def test_missing_or_invalid_tenant_is_forbidden_before_query_checks(self):
        self.ingest(1)
        for tenant in (None, "bad tenant!", "a/b"):
            for query in ("", "limit=0", "limit=101", "cursor=not-a-cursor",
                          "limit=1&limit=1", "cursor=&limit=x"):
                with self.subTest(tenant=tenant, query=query):
                    status, body = self.list_batches(query, tenant=tenant)
                    self.assertEqual((status, body),
                                     (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_empty_or_malformed_cursor_is_invalid_request(self):
        for _ in range(4):
            self.ingest(1)
        valid = self.list_batches("limit=2")[1]["next_cursor"]
        body, tag = valid.split(".", 1)

        def flip_tag(encoded_tag: str) -> str:
            raw = bytearray(base64.urlsafe_b64decode(
                encoded_tag + "=" * (-len(encoded_tag) % 4)))
            raw[0] ^= 0x80
            return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

        cases = [
            "",
            "not-a-cursor",
            "a.b.c",
            body + "." + flip_tag(tag),
            "YWJj." + tag,
            body + "." + tag + "x",
        ]
        for value in cases:
            status, payload = self.list_batches(f"cursor={value}")
            self.assertEqual((status, payload),
                             (400, {"error": "invalid_request"}), value)

    def test_records_listing_cursor_does_not_replay_on_batch_listing(self):
        # Cursors are namespaced: a cursor minted by GET /v1/records must be
        # rejected here even though both listings share one HMAC key.
        self.request("POST", "/v1/records", {"id": "r0", "plaintext": "x"})
        self.request("POST", "/v1/records", {"id": "r1", "plaintext": "x"})
        records_cursor = self.request("GET", "/v1/records?limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.list_batches(f"cursor={records_cursor}"),
            (400, {"error": "invalid_request"}),
        )

    def test_cursor_from_other_tenant_is_rejected(self):
        for _ in range(4):
            self.ingest(1, tenant="alpha")
        cursor = self.list_batches("limit=2", tenant="alpha")[1]["next_cursor"]
        self.assertEqual(self.list_batches(f"cursor={cursor}", tenant="beta"),
                         (400, {"error": "invalid_request"}))

    # -- storage failures ---------------------------------------------------

    def test_storage_failure_on_fresh_snapshot_is_503_bare_error(self):
        self.ingest(1)
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        self.assertEqual(self.list_batches(), (503, {"error": "storage_error"}))

    def test_frozen_cursor_pages_survive_later_storage_failure(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(4)]
        cursor = self.list_batches("limit=2")[1]["next_cursor"]
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batches")
        raw.close()
        # The frozen page needs only the snapshot tables; it still returns.
        status, page = self.list_batches(f"cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in page["items"]], sorted(ids)[2:])
        self.assertNotIn("next_cursor", page)
        # A fresh snapshot cannot be taken without the live table.
        self.assertEqual(self.list_batches(), (503, {"error": "storage_error"}))

    def test_storage_failure_on_cursor_page_is_503(self):
        for _ in range(3):
            self.ingest(1)
        cursor = self.list_batches("limit=1")[1]["next_cursor"]
        raw = self.db()
        with raw:
            raw.execute("DROP TABLE encrypted_batch_list_snapshot_items")
        raw.close()
        self.assertEqual(self.list_batches(f"cursor={cursor}"),
                         (503, {"error": "storage_error"}))

    # -- summary integrity --------------------------------------------------

    def test_malformed_live_summary_on_first_page_is_422(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        for column, value in (
            ("record_count", 0),
            ("record_count", 101),
            ("record_count", "two"),
        ):
            self.tamper(f"UPDATE encrypted_batches SET {column}=? WHERE batch_id=?",
                        (value, batch_id))
            with self.subTest(column=column, value=value):
                self.assertEqual(self.list_batches("limit=100"),
                                 (422, {"error": "integrity_error"}))
            self.tamper(f"UPDATE encrypted_batches SET {column}=1 WHERE batch_id=?",
                        (batch_id,))
        # A BLOB bound into the TEXT-affinity column is stored as a BLOB, so a
        # non-string created_at is observable despite type affinity.
        self.tamper("UPDATE encrypted_batches SET created_at=? WHERE batch_id=?",
                    (b"not-a-string", batch_id))
        self.assertEqual(self.list_batches("limit=100"),
                         (422, {"error": "integrity_error"}))
        self.tamper("UPDATE encrypted_batches SET created_at='2026-10-02T00:00:00+00:00' "
                    "WHERE batch_id=?", (batch_id,))
        # A malformed batch id on the returned page is likewise rejected.
        self.tamper("UPDATE encrypted_batches SET batch_id='not-a-batch' "
                    "WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.list_batches("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_corrupt_summary_on_later_page_fails_only_that_page(self):
        ids = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        # limit=1 freezes all three summaries in one snapshot.
        status, first = self.list_batches("limit=1")
        self.assertEqual(status, 200)
        snapshot_id = raw_snapshot_id(self.db(), first["next_cursor"])
        # Corrupt the frozen summary at position 2 (JSON keeps stored types).
        bad = json.dumps([ids[0], 1, 42])  # created_at is not a string
        self.tamper(
            "UPDATE encrypted_batch_list_snapshot_items SET summary=? "
            "WHERE snapshot_id=? AND position=2",
            (bad, snapshot_id),
        )
        cursor = first["next_cursor"]
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1")[0], 200)
        cursor = self.list_batches(f"cursor={cursor}&limit=1")[1]["next_cursor"]
        # Page 3 is the damaged page: 422 with a bare error body.
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))

    def test_blob_created_at_on_later_page_is_frozen_and_rejected_as_422(self):
        # Type affinity cannot coerce a BLOB: a non-string created_at survives
        # freezing; the malformed page must 422 while an earlier valid page
        # still returns 200.
        ids = sorted(self.ingest(1)[1]["batch_id"] for _ in range(2))
        self.tamper("UPDATE encrypted_batches SET created_at=? WHERE batch_id=?",
                    (b"not-a-string", ids[1]))
        status, first = self.list_batches("limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(first["items"][0]["batch_id"], ids[0])
        cursor = first["next_cursor"]
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))

    def test_truncated_or_emptied_frozen_snapshot_is_422(self):
        for _ in range(3):
            self.ingest(1)
        first = self.list_batches("limit=1")[1]
        snapshot_id = raw_snapshot_id(self.db(), first["next_cursor"])
        cursor = first["next_cursor"]

        # Remove the last frozen item: the header total disagrees with the
        # actual item count, so the next page is an integrity failure rather
        # than a silently shortened listing.
        self.tamper("DELETE FROM encrypted_batch_list_snapshot_items "
                    "WHERE snapshot_id=? AND position=2", (snapshot_id,))
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))

        # Remove every item: likewise corruption.
        self.tamper("DELETE FROM encrypted_batch_list_snapshot_items WHERE snapshot_id=?",
                    (snapshot_id,))
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))

        # The pre-recorded total itself being out of range is also rejected.
        self.tamper("UPDATE encrypted_batch_list_snapshots SET total=0 WHERE snapshot_id=?",
                    (snapshot_id,))
        self.assertEqual(self.list_batches(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))

    def test_listing_adds_no_batches_records_events_or_bindings(self):
        for _ in range(3):
            self.ingest(2)
        raw = self.db()
        try:
            before = (
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
            self.assertEqual(self.walk("limit=1")[1] and 200, 200)
        raw = self.db()
        try:
            after = (
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys"
                ).fetchone()[0],
            )
        finally:
            raw.close()
        self.assertEqual(after, before)

    # -- concurrency --------------------------------------------------------

    def test_concurrent_commits_are_observed_only_as_complete_states(self):
        failures = []
        lock = threading.Lock()
        barrier = threading.Barrier(7)

        def writer(index):
            barrier.wait()
            for _ in range(10):
                status, body = self.ingest(
                    2, tenant="acme",
                    records=[sealed_record(f"w{index}_{os.urandom(6).hex()}_{i}")
                             for i in range(2)],
                )
                if status != 201:
                    with lock:
                        failures.append(("write", status, body))

        def reader():
            barrier.wait()
            for _ in range(25):
                items, _ = self.walk("limit=3")
                batch_ids = [item["batch_id"] for item in items]
                if batch_ids != sorted(batch_ids) or len(batch_ids) != len(set(batch_ids)):
                    with lock:
                        failures.append(("order", batch_ids))
                # Every visible batch must be fully committed and its summary
                # must agree with the authoritative whole-batch read.
                for item in items:
                    status, full = self.get_batch(item["batch_id"])
                    if status != 200:
                        with lock:
                            failures.append(("missing", item["batch_id"], status))
                        continue
                    if (full["count"] != item["count"]
                            or full["created_at"] != item["created_at"]
                            or len(full["records"]) != item["count"]):
                        with lock:
                            failures.append(("shape", item, full["count"]))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])


def raw_snapshot_id(connection, cursor: str) -> str:
    """Peek the snapshot id embedded in an opaque cursor.

    The HMAC proves authenticity without hiding the body; decoding the base64
    JSON directly yields the snapshot id, which is enough to tamper with the
    frozen snapshot rows for an integrity test.
    """
    encoded_body, _ = cursor.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded_body + "=="))
    connection.close()
    self_ns = "encrypted-batches"
    assert payload["ns"] == self_ns
    return payload["t"]


if __name__ == "__main__":
    unittest.main()
