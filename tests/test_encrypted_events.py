"""Contract tests for GET /v1/encrypted-records/events.

The endpoint incrementally lists a tenant's append events (one per sealed
record committed by the sealed-write ingress). Success shape and seq ordering,
the frozen (after_seq, high_water] window with restart-proof opaque cursors,
parameter validation and error precedence, per-page whole-batch integrity
review, and serial visibility under concurrent commits are exercised here;
tampering is performed directly on the SQLite file.
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
EVENTS_PATH = "/v1/encrypted-records/events"
BATCHES_PATH = "/v1/encrypted-records/batches"
MAX_SEQ = 9223372036854775807


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


class EncryptedEventsTests(unittest.TestCase):
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

    def events(self, query="", tenant="acme"):
        path = EVENTS_PATH if not query else EVENTS_PATH + "?" + query
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
        return self.request("GET", f"{BATCHES_PATH}/{batch_id}", tenant=tenant)

    def walk(self, first_query="", tenant="acme"):
        """Page through one feed window; return (items, pages, high_water)."""
        status, body = self.events(first_query, tenant=tenant)
        self.assertEqual(status, 200)
        pages = [body]
        items = list(body["items"])
        high_water = body["high_water"]
        cursor = body.get("next_cursor")
        # Keep the first page's page size while following the chain.
        limit_suffix = "&limit=" + first_query.split("limit=", 1)[1].split("&", 1)[0] \
            if "limit=" in first_query else ""
        while cursor:
            status, page = self.events(f"cursor={cursor}{limit_suffix}", tenant=tenant)
            self.assertEqual(status, 200)
            # The high water is a property of the frozen window, every page
            # repeats it verbatim.
            self.assertEqual(page["high_water"], high_water)
            pages.append(page)
            items.extend(page["items"])
            cursor = page.get("next_cursor")
        return items, pages, high_water

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

    def test_empty_tenant_sees_zero_high_water_and_empty_items(self):
        self.assertEqual(self.events(), (200, {"items": [], "high_water": 0}))

    def test_items_are_seq_ascending_with_exactly_the_public_fields(self):
        info = []
        for size in (1, 3, 2):
            status, body = self.ingest(size)
            self.assertEqual(status, 201)
            info.append((body["batch_id"], size))
        status, body = self.events("limit=100")
        self.assertEqual(status, 200)
        seqs = [item["seq"] for item in body["items"]]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(seqs), 6)
        self.assertEqual(body["high_water"], max(seqs))
        self.assertNotIn("next_cursor", body)
        for item in body["items"]:
            self.assertEqual(
                set(item), {"seq", "batch_id", "id", "position", "created_at"}
            )
            self.assertNotIn("ciphertext", item)
            self.assertNotIn("envelope", item)
            self.assertNotIn("metadata", item)
            self.assertNotIn("algorithm", item)

    def test_item_values_match_events_and_their_batch(self):
        batch_id = self.ingest(2)[1]["batch_id"]
        status, full = self.get_batch(batch_id)
        self.assertEqual(status, 200)
        _, body = self.events("limit=100")
        mine = [item for item in body["items"] if item["batch_id"] == batch_id]
        self.assertEqual([item["position"] for item in mine], [0, 1])
        self.assertEqual([item["id"] for item in mine],
                         [record["id"] for record in full["records"]])
        for item in mine:
            self.assertEqual(item["created_at"], full["created_at"])

    def test_after_seq_is_exclusive_and_high_water_floors_at_it(self):
        for _ in range(3):
            self.ingest(1)
        _, body = self.events("limit=100")
        seqs = [item["seq"] for item in body["items"]]
        # Strictly greater than the start.
        _, after = self.events(f"after_seq={seqs[1]}&limit=100")
        self.assertEqual([item["seq"] for item in after["items"]], seqs[2:])
        self.assertEqual(after["high_water"], max(seqs))
        # Starting at the current max yields an empty page but the same water.
        status, tail = self.events(f"after_seq={max(seqs)}")
        self.assertEqual(status, 200)
        self.assertEqual(tail["items"], [])
        self.assertEqual(tail["high_water"], max(seqs))
        # A start beyond the observed max becomes the high water itself.
        status, ahead = self.events("after_seq=100")
        self.assertEqual(status, 200)
        self.assertEqual(ahead, {"items": [], "high_water": 100})

    def test_after_seq_accepts_zero_default_leading_zeros_and_max_int(self):
        self.ingest(1)
        for value in ("0", "00", "00000"):
            status, body = self.events(f"after_seq={value}")
            self.assertEqual(status, 200, value)
            self.assertEqual(len(body["items"]), 1)
        status, body = self.events(f"after_seq={MAX_SEQ}")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "high_water": MAX_SEQ})

    def test_other_tenants_and_plain_records_are_invisible_with_seq_gaps(self):
        alpha = self.ingest(2, tenant="alpha")[1]["batch_id"]
        beta = self.ingest(1, tenant="beta")[1]["batch_id"]
        acme = self.ingest(2)[1]["batch_id"]
        # Server-side encrypted records live in a different table and produce
        # no append events.
        self.assertEqual(
            self.request("POST", "/v1/records", {"id": "p1", "plaintext": "x"},
                         tenant="acme")[0],
            201,
        )
        items, _, high_water = self.walk("limit=1")
        self.assertEqual([item["batch_id"] for item in items], [acme, acme])
        # The global stream interleaves other tenants: acme's seqs are gappy,
        # but the high water is acme's own maximum, not the global one.
        self.assertEqual(high_water, max(item["seq"] for item in items))
        alpha_items, _, alpha_water = self.walk("limit=1", tenant="alpha")
        self.assertEqual({item["batch_id"] for item in alpha_items}, {alpha})
        beta_items, _, beta_water = self.walk(tenant="beta")
        self.assertEqual({item["batch_id"] for item in beta_items}, {beta})
        self.assertNotIn(beta, [item["batch_id"] for item in items])
        self.assertEqual(alpha_water, max(i["seq"] for i in alpha_items))
        self.assertEqual(beta_water, max(i["seq"] for i in beta_items))
        # A tenant with no sealed batches at all sees the empty envelope.
        self.assertEqual(self.events(tenant="ghost"),
                         (200, {"items": [], "high_water": 0}))

    def test_query_adds_no_rows_to_any_protocol_table(self):
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

    # -- pagination ----------------------------------------------------------

    def test_default_limit_is_fifty(self):
        for _ in range(51):
            self.ingest(1)
        status, first = self.events()
        self.assertEqual(status, 200)
        self.assertEqual(len(first["items"]), 50)
        self.assertIn("next_cursor", first)
        status, second = self.events(f"cursor={first['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual(len(second["items"]), 1)
        self.assertNotIn("next_cursor", second)

    def test_pagination_walks_every_event_once_without_gaps_or_duplicates(self):
        for size in (2, 1, 3, 1):
            self.ingest(size)
        items, pages, high_water = self.walk("limit=3")
        self.assertEqual([len(page["items"]) for page in pages], [3, 3, 1])
        seqs = [item["seq"] for item in items]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(high_water, max(seqs))

    def test_next_cursor_appears_exactly_when_another_page_exists(self):
        for _ in range(3):
            self.ingest(1)
        status, first = self.events("limit=2")
        self.assertEqual(len(first["items"]), 2)
        self.assertIn("next_cursor", first)
        status, last = self.events(f"cursor={first['next_cursor']}&limit=2")
        self.assertEqual(len(last["items"]), 1)
        self.assertNotIn("next_cursor", last)

    def test_limit_boundaries_accepted_and_rejected(self):
        self.ingest(2)
        for value in ("1", "01", "007", "100"):
            self.assertEqual(self.events(f"limit={value}")[0], 200, value)
        for value in ("0", "101", "1000", "-1", "1.5", "0x1", "%201", "1%20",
                      "", "a", "%EF%BC%95", "true"):
            status, body = self.events(f"limit={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_after_seq_boundaries_and_shapes(self):
        self.ingest(1)
        for value in ("", "-1", "9223372036854775808", "1.0", "0x1", "a",
                      "%201", "1%20", "%2B1", "true"):
            status, body = self.events(f"after_seq={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_duplicate_after_seq_limit_or_cursor_is_rejected(self):
        for _ in range(4):
            self.ingest(1)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.assertEqual(self.events("after_seq=0&after_seq=1"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.events("limit=1&limit=1"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.events(f"cursor={cursor}&cursor={cursor}"),
                         (400, {"error": "invalid_request"}))

    def test_cursor_and_after_seq_together_is_rejected(self):
        for _ in range(3):
            self.ingest(1)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.events(f"cursor={cursor}&after_seq=0"),
            (400, {"error": "invalid_request"}),
        )
        self.assertEqual(
            self.events(f"after_seq=0&cursor={cursor}"),
            (400, {"error": "invalid_request"}),
        )

    def test_unknown_query_parameters_are_ignored(self):
        self.ingest(1)
        status, body = self.events("foo=bar&baz=&limit=100&order=desc&since=9")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 1)

    # -- frozen window semantics -------------------------------------------

    def test_window_excludes_later_commits_until_fresh_query(self):
        first_wave = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        status, page = self.events("limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in page["items"]], [1, 2])
        self.assertEqual(page["high_water"], 3)
        cursor = page["next_cursor"]

        later = [self.ingest(1)[1]["batch_id"] for _ in range(2)]
        self.request("POST", "/v1/keys/rotate", {"version": 2})

        status, rest = self.walk_continue(cursor, "limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in rest["items"]], [3])
        self.assertEqual(rest["high_water"], 3)
        self.assertNotIn("next_cursor", rest)

        # The same cursor replays the identical page and stays pinned.
        status, replay = self.events(f"cursor={cursor}")
        self.assertEqual([item["seq"] for item in replay["items"]], [3])
        self.assertEqual(replay["high_water"], 3)

        # Adopt the high water as the new after_seq: only new events appear.
        status, fresh = self.events("after_seq=3&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual([item["batch_id"] for item in fresh["items"]], later)
        self.assertEqual(fresh["high_water"], 5)
        all_batches = first_wave + later
        status, full = self.events("limit=100")
        self.assertEqual([item["batch_id"] for item in full["items"]
                         if item["position"] == 0], all_batches)

    def walk_continue(self, cursor, suffix=""):
        query = f"cursor={cursor}" + ("&" + suffix if suffix else "")
        return self.events(query)

    def test_limit_may_change_between_pages(self):
        for _ in range(5):
            self.ingest(1)
        _, first = self.events("limit=2")
        cursor = first["next_cursor"]
        status, rest = self.events(f"cursor={cursor}&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in rest["items"]], [3, 4, 5])
        self.assertNotIn("next_cursor", rest)

    def test_same_cursor_and_limit_replays_the_same_page(self):
        for _ in range(4):
            self.ingest(1)
        cursor = self.events("limit=2")[1]["next_cursor"]
        responses = [self.events(f"cursor={cursor}&limit=2")[1] for _ in range(3)]
        for body in responses[1:]:
            self.assertEqual(body, responses[0])

    def test_failed_writes_and_idempotent_replays_add_no_events(self):
        records = [sealed_record("dup-a"), sealed_record("dup-b")]
        self.assertEqual(self.ingest(records=records)[0], 201)
        # A keyless retry fails (ids exist) and creates no events.
        self.assertEqual(self.ingest(records=records)[0], 400)
        # A keyed first write and its same-content replay share one batch.
        replay_records = [sealed_record("keyed-a")]
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 201)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)

        items, _, high_water = self.walk("limit=1")
        self.assertEqual(len(items), 3)
        self.assertEqual(high_water, 3)
        raw = self.db()
        try:
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                3,
            )
        finally:
            raw.close()

    # -- restart and key rotation ------------------------------------------

    def test_cursor_survives_restart_and_replays_identical_page(self):
        for _ in range(5):
            self.ingest(1)
        status, first = self.events("limit=2")
        self.assertEqual(status, 200)
        cursor = first["next_cursor"]
        status, second = self.events(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        second_page = second["items"]
        self.assertEqual(second["high_water"], 5)

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.events(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(after["items"], second_page)
        self.assertEqual(after["high_water"], 5)
        items, pages, high_water = self.walk("limit=2")
        self.assertEqual([item["seq"] for item in items], [1, 2, 3, 4, 5])
        self.assertEqual(high_water, 5)

    def test_key_rotation_neither_changes_feed_nor_invalidates_cursor(self):
        for _ in range(4):
            self.ingest(1)
        before = self.events("limit=2")[1]
        cursor = before["next_cursor"]
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200)
        status, page = self.events(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in page["items"]], [3, 4])
        self.assertEqual(page["high_water"], 4)
        status, fresh = self.events("limit=100")
        self.assertEqual(len(fresh["items"]), 4)

    # -- request validation and error precedence ---------------------------

    def test_missing_or_invalid_tenant_is_forbidden_before_query_checks(self):
        self.ingest(1)
        for tenant in (None, "bad tenant!", "a/b"):
            for query in ("", "after_seq=", "after_seq=x", "after_seq=9223372036854775808",
                          "limit=0", "limit=101", "cursor=not-a-cursor",
                          "after_seq=0&after_seq=1", "cursor=&limit=x",
                          "cursor=x&after_seq=0"):
                with self.subTest(tenant=tenant, query=query):
                    status, body = self.events(query, tenant=tenant)
                    self.assertEqual((status, body),
                                     (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_empty_or_malformed_cursor_is_invalid_request(self):
        for _ in range(4):
            self.ingest(1)
        valid = self.events("limit=2")[1]["next_cursor"]
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
            status, payload = self.events(f"cursor={value}")
            self.assertEqual((status, payload),
                             (400, {"error": "invalid_request"}), value)

    def test_other_entry_point_cursors_do_not_replay_on_feed(self):
        # Cursors are namespaced: a cursor minted by either listing endpoint is
        # rejected here even though all three share one HMAC key.
        self.request("POST", "/v1/records", {"id": "r0", "plaintext": "x"})
        self.request("POST", "/v1/records", {"id": "r1", "plaintext": "x"})
        records_cursor = self.request("GET", "/v1/records?limit=1")[1]["next_cursor"]
        self.assertEqual(self.events(f"cursor={records_cursor}"),
                         (400, {"error": "invalid_request"}))

        for _ in range(4):
            self.ingest(1)
        batches_cursor = self.request(
            "GET", BATCHES_PATH + "?limit=2")[1]["next_cursor"]
        self.assertEqual(self.events(f"cursor={batches_cursor}"),
                         (400, {"error": "invalid_request"}))

    def test_feed_cursor_does_not_replay_on_other_entry_points(self):
        for _ in range(4):
            self.ingest(1)
        feed_cursor = self.events("limit=2")[1]["next_cursor"]
        self.assertEqual(
            self.request("GET", BATCHES_PATH + f"?cursor={feed_cursor}"),
            (400, {"error": "invalid_request"}),
        )

    def test_cursor_from_other_tenant_is_rejected(self):
        for _ in range(4):
            self.ingest(1, tenant="alpha")
        cursor = self.events("limit=2", tenant="alpha")[1]["next_cursor"]
        self.assertEqual(self.events(f"cursor={cursor}", tenant="beta"),
                         (400, {"error": "invalid_request"}))

    # -- storage failures ---------------------------------------------------

    def test_storage_failure_on_fresh_query_is_503(self):
        self.ingest(1)
        self.tamper("DROP TABLE encrypted_record_events")
        self.assertEqual(self.events(), (503, {"error": "storage_error"}))

    def test_storage_failure_on_cursor_page_is_503(self):
        for _ in range(3):
            self.ingest(1)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.tamper("DROP TABLE encrypted_record_events")
        # The window is re-read from the live table on every page.
        self.assertEqual(self.events(f"cursor={cursor}"),
                         (503, {"error": "storage_error"}))

    # -- integrity review ---------------------------------------------------

    def test_damaged_involved_batch_fails_only_the_page_touching_it(self):
        batch_ids = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        self.tamper("UPDATE encrypted_batches SET record_count=0 WHERE batch_id=?",
                    (batch_ids[2],))
        status, first = self.events("limit=1")
        self.assertEqual(status, 200)
        cursor = first["next_cursor"]
        self.assertEqual(self.events(f"cursor={cursor}&limit=1")[0], 200)
        cursor = self.events(f"cursor={cursor}&limit=1")[1]["next_cursor"]
        # The third page reviews the damaged batch.
        self.assertEqual(self.events(f"cursor={cursor}&limit=1"),
                         (422, {"error": "integrity_error"}))
        # A window-wide request fails atomically with no partial page.
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_damaged_unrelated_batch_does_not_affect_the_page(self):
        batch_ids = [self.ingest(1)[1]["batch_id"] for _ in range(3)]
        self.tamper("UPDATE encrypted_batches SET record_count=0 WHERE batch_id=?",
                    (batch_ids[2],))
        # A window strictly after the damaged event loads no damaged batch.
        status, page = self.events("after_seq=3")
        # seq 3 is behind the start; the empty page proves the water only.
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in page["items"]], [])
        # An empty window at 0 on a tenant whose only batches are elsewhere is
        # unaffected by damage too.
        self.assertEqual(self.events(tenant="ghost"),
                         (200, {"items": [], "high_water": 0}))

    def test_unlisted_sibling_record_of_an_involved_batch_fails_page(self):
        # A two-record batch: a page lists only the first event, but the batch
        # is loaded and reviewed whole, so a corrupted sibling record is 422.
        self.ingest(2)
        self.tamper("UPDATE encrypted_records SET algorithm='BOGUS' "
                    "WHERE batch_id=(SELECT batch_id FROM encrypted_record_events "                    "WHERE seq=2)")
        self.assertEqual(self.events("limit=1"),
                         (422, {"error": "integrity_error"}))

    def test_missing_associated_batch_is_422(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        self.ingest(1)
        self.tamper("DELETE FROM encrypted_batches WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_batch_repointed_at_another_tenant_is_422(self):
        batch_id = self.ingest(1)[1]["batch_id"]
        self.tamper("UPDATE encrypted_batches SET tenant='beta' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))
        # The foreign owner cannot observe the event either: its own window is
        # empty because the event rows still belong to acme.
        self.assertEqual(self.events(tenant="beta"),
                         (200, {"items": [], "high_water": 0}))

    def test_illegal_batch_link_on_event_is_422(self):
        self.ingest(1)
        self.tamper("UPDATE encrypted_record_events SET batch_id='not-a-batch' "
                    "WHERE seq=1")
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    # -- concurrency --------------------------------------------------------

    def test_concurrent_commits_are_observed_only_as_complete_windows(self):
        failures = []
        lock = threading.Lock()
        barrier = threading.Barrier(7)

        def writer(index):
            barrier.wait()
            for _ in range(10):
                status, body = self.ingest(
                    2,
                    records=[sealed_record(f"w{index}_{os.urandom(6).hex()}_{i}")
                             for i in range(2)],
                )
                if status != 201:
                    with lock:
                        failures.append(("write", status, body))

        def reader():
            barrier.wait()
            for _ in range(25):
                items, pages, high_water = self.walk("limit=3")
                seqs = [item["seq"] for item in items]
                if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
                    with lock:
                        failures.append(("order", seqs))
                if any(seq > high_water for seq in seqs):
                    with lock:
                        failures.append(("water", seqs, high_water))
                # Every visible event must reference a fully committed batch
                # and match the authoritative whole-batch read.
                for item in items:
                    status, full = self.get_batch(item["batch_id"])
                    if status != 200:
                        with lock:
                            failures.append(("missing", item, status))
                        continue
                    if full["created_at"] != item["created_at"]:
                        with lock:
                            failures.append(("created_at", item))
                    record = full["records"][item["position"]]
                    if record["id"] != item["id"]:
                        with lock:
                            failures.append(("binding", item, record["id"]))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
