"""Contract tests for GET /v1/encrypted-records/events.

The endpoint incrementally lists a tenant's append events (one per sealed
record committed by the sealed-write ingress) by global event sequence.
Success shape and ordering, the fixed serial-instant water mark, cursor
continuation with restart-proof namespaced cursors, error precedence
(403 before parameters, 503 before 422), whole-batch integrity re-validation
of every batch touched by the page (and only those), and serial visibility
under concurrent commits are all exercised here; tampering is performed
directly on the SQLite file.
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
MAX_SEQ = 9_223_372_036_854_775_807


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


class EncryptedRecordEventsTests(unittest.TestCase):
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
        """Follow an event chain; return (items, pages).

        A ``limit`` in the first query is carried verbatim on every
        continuation, so the chain keeps one fixed page size.
        """
        status, body = self.events(first_query, tenant=tenant)
        self.assertEqual(status, 200)
        pages = [body]
        items = list(body["items"])
        cursor = body.get("next_cursor")
        limit_suffix = ""
        for segment in first_query.split("&"):
            name, equals, value = segment.partition("=")
            if equals and name == "limit":
                limit_suffix = f"&limit={value}"
        while cursor:
            status, page = self.events(f"cursor={cursor}{limit_suffix}", tenant=tenant)
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

    def tenant_events_raw(self, tenant="acme"):
        raw = self.db()
        try:
            rows = raw.execute(
                "SELECT seq, batch_id, record_id, position "
                "FROM encrypted_record_events WHERE tenant=? ORDER BY seq ASC",
                (tenant,),
            ).fetchall()
            return [tuple(row) for row in rows]
        finally:
            raw.close()

    # -- success shape and ordering ----------------------------------------

    def test_empty_tenant_returns_empty_items_and_zero_water(self):
        self.assertEqual(self.events(), (200, {"items": [], "high_water": 0}))

    def test_empty_tenant_explicit_after_seq_is_reflected_in_water(self):
        # Empty tenant's max seq is 0, so the water is max(after_seq, 0).
        self.assertEqual(
            self.events("after_seq=0050"),
            (200, {"items": [], "high_water": 50}),
        )

    def test_items_have_exact_shape_without_ciphertext_or_envelope(self):
        self.ingest(2)
        status, body = self.events("limit=100")
        self.assertEqual(status, 200)
        self.assertNotIn("next_cursor", body)
        self.assertEqual(set(body), {"items", "high_water"})
        self.assertEqual(len(body["items"]), 2)
        for item in body["items"]:
            self.assertEqual(set(item), {"seq", "batch_id", "id", "position", "created_at"})
            self.assertNotIn("ciphertext", item)
            self.assertNotIn("envelope", item)
            self.assertNotIn("algorithm", item)
            self.assertNotIn("metadata", item)

    def test_items_match_stored_events_and_batch_rows_in_seq_order(self):
        first = self.ingest(2)[1]["batch_id"]
        second = self.ingest(1)[1]["batch_id"]
        raw_events = self.tenant_events_raw()
        status, body = self.events("limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(body["high_water"], raw_events[-1][0])
        for item, (seq, batch_id, record_id, position) in zip(body["items"], raw_events):
            self.assertEqual(item["seq"], seq)
            self.assertEqual(item["batch_id"], batch_id)
            self.assertEqual(item["id"], record_id)
            self.assertEqual(item["position"], position)
            status, full = self.get_batch(batch_id)
            self.assertEqual(status, 200)
            self.assertEqual(item["created_at"], full["created_at"])
        # Records within one batch are observed in position order.
        self.assertEqual(
            [(item["batch_id"], item["position"]) for item in body["items"]],
            [(first, 0), (first, 1), (second, 0)],
        )
        seqs = [item["seq"] for item in body["items"]]
        self.assertEqual(seqs, sorted(seqs))

    def test_other_tenants_and_server_side_records_are_invisible_with_gaps(self):
        # Global sequence interleaves tenants; each tenant must see only its
        # own events, with legitimate gaps in the seq numbers.
        alpha_first = self.ingest(1, tenant="alpha")[1]["batch_id"]
        beta_first = self.ingest(1, tenant="beta")[1]["batch_id"]
        alpha_second = self.ingest(2, tenant="alpha")[1]["batch_id"]
        beta_second = self.ingest(1, tenant="beta")[1]["batch_id"]
        # A server-side encrypted record never becomes an event.
        self.assertEqual(
            self.request("POST", "/v1/records", {"id": "p1", "plaintext": "x"},
                         tenant="alpha")[0],
            201,
        )

        alpha_items, _ = self.walk("limit=1", tenant="alpha")
        beta_items, _ = self.walk("limit=1", tenant="beta")
        alpha_raw = self.tenant_events_raw("alpha")
        beta_raw = self.tenant_events_raw("beta")
        self.assertEqual([item["seq"] for item in alpha_items], [row[0] for row in alpha_raw])
        self.assertEqual([item["seq"] for item in beta_items], [row[0] for row in beta_raw])
        self.assertEqual(
            {item["batch_id"] for item in alpha_items},
            {alpha_first, alpha_second},
        )
        self.assertEqual(
            {item["batch_id"] for item in beta_items}, {beta_first, beta_second})
        self.assertEqual(len(beta_items), 2)
        # Alpha's seqs are non-contiguous because beta committed in between.
        alpha_seqs = [row[0] for row in alpha_raw]
        self.assertNotEqual(alpha_seqs, list(range(alpha_seqs[0], alpha_seqs[-1] + 1)))
        self.assertEqual(self.events(tenant="ghost"),
                         (200, {"items": [], "high_water": 0}))

    def test_after_seq_is_exclusive_and_water_pins_the_range(self):
        self.ingest(3)
        raw = self.tenant_events_raw()
        seqs = [row[0] for row in raw]
        # Start exactly at the second event: that seq is excluded.
        status, body = self.events(f"after_seq={seqs[1]}&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(body["high_water"], seqs[-1])
        self.assertEqual([item["seq"] for item in body["items"]], seqs[2:])

        # after_seq at (and beyond) the tip yields an empty final page with the
        # water pinned to max(after_seq, current max).
        self.assertEqual(
            self.events(f"after_seq={seqs[-1]}"),
            (200, {"items": [], "high_water": seqs[-1]}),
        )
        self.assertEqual(
            self.events(f"after_seq={seqs[-1] + 100}"),
            (200, {"items": [], "high_water": seqs[-1] + 100}),
        )

    def test_leading_zeros_on_after_seq_are_accepted(self):
        self.ingest(2)
        seqs = [row[0] for row in self.tenant_events_raw()]
        status, body = self.events(f"after_seq=00000{seqs[0]}&limit=001")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in body["items"]], seqs[1:])

    def test_query_changes_nothing(self):
        batch_id = self.ingest(2)[1]["batch_id"]
        raw = self.db()
        try:
            before = (
                tuple(raw.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id=?", (batch_id,)).fetchone()),
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys").fetchone()[0],
            )
        finally:
            raw.close()
        for _ in range(3):
            self.assertEqual(self.walk("limit=1")[1] and 200, 200)
        raw = self.db()
        try:
            after = (
                tuple(raw.execute(
                    "SELECT batch_id, tenant, record_count, created_at "
                    "FROM encrypted_batches WHERE batch_id=?", (batch_id,)).fetchone()),
                raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys").fetchone()[0],
            )
        finally:
            raw.close()
        self.assertEqual(after, before)

    # -- pagination ---------------------------------------------------------

    def test_default_limit_is_fifty(self):
        self.ingest(51)
        status, first = self.events()
        self.assertEqual(status, 200)
        self.assertEqual(len(first["items"]), 50)
        self.assertIn("next_cursor", first)
        water = first["high_water"]
        status, second = self.events(f"cursor={first['next_cursor']}")
        self.assertEqual(status, 200)
        self.assertEqual(len(second["items"]), 1)
        self.assertNotIn("next_cursor", second)
        self.assertEqual(second["high_water"], water)

    def test_pagination_walks_every_event_once_without_gaps(self):
        for size in (1, 3, 2, 4):
            self.ingest(size)
        items, pages = self.walk("limit=2")
        self.assertEqual([len(page["items"]) for page in pages], [2, 2, 2, 2, 2])
        seqs = [item["seq"] for item in items]
        self.assertEqual(seqs, [row[0] for row in self.tenant_events_raw()])
        self.assertEqual(len(seqs), len(set(seqs)))
        waters = {page["high_water"] for page in pages}
        self.assertEqual(waters, {seqs[-1]})

    def test_next_cursor_appears_exactly_when_more_events_are_in_range(self):
        self.ingest(3)
        seqs = [row[0] for row in self.tenant_events_raw()]
        # Range covers only the last two events; the first page of size one
        # must hand back a cursor even though an earlier event exists.
        status, first = self.events(f"after_seq={seqs[0]}&limit=1")
        self.assertEqual([item["seq"] for item in first["items"]], [seqs[1]])
        self.assertIn("next_cursor", first)
        status, last = self.events(f"cursor={first['next_cursor']}&limit=1")
        self.assertEqual([item["seq"] for item in last["items"]], [seqs[2]])
        self.assertNotIn("next_cursor", last)

    def test_limit_boundaries_accepted_and_rejected(self):
        self.ingest(2)
        for value in ("1", "01", "007", "100"):
            self.assertEqual(self.events(f"limit={value}")[0], 200, value)
        for value in ("0", "101", "1000", "-1", "1.5", "0x1", "%201", "1%20",
                      "", "a", "%EF%BC%95", "true"):
            status, body = self.events(f"limit={value}")
            self.assertEqual((status, body), (400, {"error": "invalid_request"}), value)

    def test_after_seq_boundaries_accepted_and_rejected(self):
        self.ingest(1)
        for value in ("0", "00", "0000", "007", str(MAX_SEQ)):
            self.assertEqual(self.events(f"after_seq={value}")[0], 200, value)
        # The maximum stays accepted even when zero-padded past 19 digits.
        self.assertEqual(self.events(f"after_seq=0{MAX_SEQ}")[0], 200)
        for value in ("", "-1", "-0", "1.5", "0x1", "1_000", "+1",
                      str(MAX_SEQ + 1), "999999999999999999999",
                      "9" * 5000, "a", "%EF%BC%90", "%20", "true"):
            with self.subTest(value=value[:12]):
                status, body = self.events(f"after_seq={value}")
                self.assertEqual((status, body), (400, {"error": "invalid_request"}))

    def test_duplicate_known_parameters_are_rejected(self):
        self.ingest(3)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.assertEqual(self.events("limit=1&limit=1"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.events("after_seq=0&after_seq=0"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(self.events(f"cursor={cursor}&cursor={cursor}"),
                         (400, {"error": "invalid_request"}))

    def test_cursor_and_after_seq_together_is_rejected(self):
        self.ingest(2)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.events(f"cursor={cursor}&after_seq=0"),
            (400, {"error": "invalid_request"}),
        )
        self.assertEqual(
            self.events(f"after_seq=0&cursor={cursor}&limit=1"),
            (400, {"error": "invalid_request"}),
        )

    def test_unknown_query_parameters_are_ignored(self):
        self.ingest(1)
        seq = self.tenant_events_raw()[0][0]
        status, body = self.events("foo=bar&baz=&limit=100&order=desc&after_seq=00")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in body["items"]], [seq])

    # -- frozen water semantics --------------------------------------------

    def test_water_excludes_later_commits_until_fresh_query(self):
        self.ingest(3)
        first_seqs = [row[0] for row in self.tenant_events_raw()]
        status, page = self.events("limit=2")
        self.assertEqual([item["seq"] for item in page["items"]], first_seqs[:2])
        cursor = page["next_cursor"]
        water = page["high_water"]

        # Commits and a rotation after the instant is fixed stay out of the
        # chain, even though new global seqs now exist.
        self.ingest(3)
        self.request("POST", "/v1/keys/rotate", {"version": 2})

        status, second = self.events(f"cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual(second["high_water"], water)
        self.assertEqual([item["seq"] for item in second["items"]], first_seqs[2:])
        self.assertNotIn("next_cursor", second)

        # The same cursor replays the identical page.
        status, replay = self.events(f"cursor={cursor}")
        self.assertEqual(replay, second)

        # Resuming at the returned water surfaces only the later commits.
        later_seqs = [row[0] for row in self.tenant_events_raw()][3:]
        status, resumed = self.events(f"after_seq={water}&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in resumed["items"]], later_seqs)
        self.assertNotIn("next_cursor", resumed)

    def test_limit_may_change_between_pages(self):
        self.ingest(5)
        seqs = [row[0] for row in self.tenant_events_raw()]
        _, first = self.events("limit=2")
        cursor = first["next_cursor"]
        status, rest = self.events(f"cursor={cursor}&limit=10")
        self.assertEqual(status, 200)
        self.assertEqual([item["seq"] for item in rest["items"]], seqs[2:])
        self.assertNotIn("next_cursor", rest)

    def test_same_cursor_and_limit_replays_the_same_page(self):
        self.ingest(4)
        cursor = self.events("limit=2")[1]["next_cursor"]
        responses = [self.events(f"cursor={cursor}&limit=2")[1] for _ in range(3)]
        for body in responses[1:]:
            self.assertEqual(body, responses[0])

    def test_failed_writes_and_idempotent_replays_add_no_events(self):
        records = [sealed_record("dup-a"), sealed_record("dup-b")]
        self.assertEqual(self.ingest(records=records)[0], 201)
        # A keyless retry fails (ids exist) and creates no events.
        self.assertEqual(self.ingest(records=records)[0], 400)
        # A keyed first write and its same-content replays share one batch.
        replay_records = [sealed_record("keyed-a")]
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 201)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)
        self.assertEqual(self.ingest(records=replay_records, key="k-1")[0], 200)

        items, pages = self.walk("limit=1")
        self.assertEqual([item["id"] for item in items], ["dup-a", "dup-b", "keyed-a"])
        raw = self.db()
        try:
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0], 2)
            self.assertEqual(
                raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0], 3)
            self.assertEqual(
                raw.execute(
                    "SELECT COUNT(*) FROM encrypted_batch_idempotency_keys").fetchone()[0], 1)
        finally:
            raw.close()

    # -- restart and key rotation ------------------------------------------

    def test_cursor_survives_restart_and_replays_identical_page(self):
        self.ingest(5)
        status, first = self.events("limit=2")
        self.assertEqual(status, 200)
        cursor = first["next_cursor"]
        status, second = self.events(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        second_page = second["items"]
        water = second["high_water"]

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.events(f"cursor={cursor}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(after["items"], second_page)
        self.assertEqual(after["high_water"], water)
        # A fresh query after restart works unchanged.
        items, _ = self.walk("limit=2")
        self.assertEqual(
            [item["seq"] for item in items],
            [row[0] for row in self.tenant_events_raw()],
        )

    def test_key_rotation_neither_changes_events_nor_invalidates_cursor(self):
        self.ingest(4)
        before = self.events("limit=2")[1]
        cursor = before["next_cursor"]
        self.assertEqual(self.request("POST", "/v1/keys/rotate", {"version": 2})[0], 200)
        first_replay = self.events(f"cursor={cursor}&limit=2")[1]
        second_replay = self.events(f"cursor={cursor}&limit=2")[1]
        self.assertEqual(first_replay, second_replay)
        self.assertEqual(
            [item["seq"] for item in first_replay["items"]],
            [row[0] for row in self.tenant_events_raw()][2:],
        )

    # -- request validation and error precedence ---------------------------

    def test_missing_or_invalid_tenant_is_forbidden_before_query_checks(self):
        self.ingest(1)
        for tenant in (None, "bad tenant!", "a/b"):
            for query in ("", "limit=0", "limit=101", "cursor=not-a-cursor",
                          "after_seq=", f"after_seq={MAX_SEQ + 1}",
                          "after_seq=0&after_seq=0", "limit=1&limit=1"):
                with self.subTest(tenant=tenant, query=query):
                    self.assertEqual(self.events(query, tenant=tenant),
                                     (403, {"error": "TENANT_RECORD_FORBIDDEN"}))

    def test_empty_or_malformed_cursor_is_invalid_request(self):
        self.ingest(4)
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
            self.assertEqual(self.events(f"cursor={value}"),
                             (400, {"error": "invalid_request"}), value)

    def test_cursors_from_other_entry_points_do_not_replay(self):
        # Cursors are namespaced: a cursor minted by another listing endpoint
        # shares the HMAC key but must be rejected here.
        self.ingest(1)
        self.ingest(1)
        batch_cursor = self.request("GET", BATCHES_PATH + "?limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.events(f"cursor={batch_cursor}"),
            (400, {"error": "invalid_request"}),
        )
        self.request("POST", "/v1/records", {"id": "r0", "plaintext": "x"})
        self.request("POST", "/v1/records", {"id": "r1", "plaintext": "x"})
        records_cursor = self.request("GET", "/v1/records?limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.events(f"cursor={records_cursor}"),
            (400, {"error": "invalid_request"}),
        )
        # An event cursor does not replay on the batch listing either.
        event_cursor = self.events("limit=1")[1]["next_cursor"]
        self.assertEqual(
            self.request("GET", BATCHES_PATH + f"?cursor={event_cursor}"),
            (400, {"error": "invalid_request"}),
        )

    def test_cursor_from_other_tenant_is_rejected(self):
        self.ingest(4, tenant="alpha")
        cursor = self.events("limit=2", tenant="alpha")[1]["next_cursor"]
        self.assertEqual(self.events(f"cursor={cursor}", tenant="beta"),
                         (400, {"error": "invalid_request"}))

    # -- storage failures ---------------------------------------------------

    def test_storage_failure_on_max_read_is_503_bare_error(self):
        self.ingest(1)
        self.tamper("DROP TABLE encrypted_record_events")
        self.assertEqual(self.events(), (503, {"error": "storage_error"}))

    def test_storage_failure_loading_involved_batches_is_503(self):
        self.ingest(2)
        cursor = self.events("limit=1")[1]["next_cursor"]
        self.tamper("DROP TABLE encrypted_batches")
        self.assertEqual(self.events(f"cursor={cursor}"),
                         (503, {"error": "storage_error"}))

    def test_storage_failure_on_first_page_event_read_is_503(self):
        self.ingest(1)
        self.tamper("DROP TABLE encrypted_records")
        # Events are readable, but the whole-batch review load fails -> 503,
        # never a 422 built on a failed query.
        self.assertEqual(self.events("limit=100"),
                         (503, {"error": "storage_error"}))

    # -- integrity ----------------------------------------------------------

    def test_involved_batch_row_missing_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("DELETE FROM encrypted_batches WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_involved_batch_repointed_at_another_tenant_is_422(self):
        self.ingest(1, tenant="alpha")
        batch_id = self.tenant_events_raw("alpha")[0][1]
        self.tamper("UPDATE encrypted_batches SET tenant='beta' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=100", tenant="alpha"),
                         (422, {"error": "integrity_error"}))

    def test_illegal_batch_id_on_event_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_record_events SET batch_id='not-a-batch' "
                    "WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_damaged_record_in_involved_batch_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_records SET algorithm='ROT13' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_batch_count_drift_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_batches SET record_count=2 WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_event_record_mismatch_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_record_events SET record_id='other-id' "
                    "WHERE batch_id=?", (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_unrelated_damaged_batch_does_not_affect_the_page(self):
        # An earlier corrupt batch is skipped with after_seq; a later query
        # whose page only touches the healthy batch still returns 200.
        damaged = self.ingest(1)[1]["batch_id"]
        healthy_events = self.ingest(2)
        self.assertEqual(healthy_events[0], 201)
        last_damaged_seq = max(
            row[0] for row in self.tenant_events_raw() if row[1] == damaged
        )
        # Corrupt the early batch (missing record).
        self.tamper("DELETE FROM encrypted_records WHERE batch_id=?", (damaged,))
        status, body = self.events(f"after_seq={last_damaged_seq}&limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 2)
        self.assertTrue(all(item["batch_id"] != damaged for item in body["items"]))
        # Starting before it, the same corruption does fail the page that
        # touches it.
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_tampered_event_position_is_422(self):
        self.ingest(1)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_record_events SET position=7 WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=100"),
                         (422, {"error": "integrity_error"}))

    def test_integrity_failure_returns_bare_error_without_partial_page(self):
        # All three events belong to one corrupt batch. Even the first page,
        # which would render two items, is refused wholesale: the whole-batch
        # review runs before any item is returned.
        self.ingest(3)
        batch_id = self.tenant_events_raw()[0][1]
        self.tamper("UPDATE encrypted_records SET algorithm='ROT13' WHERE batch_id=?",
                    (batch_id,))
        self.assertEqual(self.events("limit=2"),
                         (422, {"error": "integrity_error"}))

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
                items, pages = self.walk("limit=3")
                seqs = [item["seq"] for item in items]
                if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
                    with lock:
                        failures.append(("order", seqs))
                # Every page keeps the first page's water; every visible event
                # must belong to a fully committed, readable batch.
                waters = {page["high_water"] for page in pages}
                if len(waters) != 1:
                    with lock:
                        failures.append(("water", waters))
                for item in items:
                    status, full = self.get_batch(item["batch_id"])
                    if status != 200:
                        with lock:
                            failures.append(("missing", item["batch_id"], status))
                        continue
                    if (item["created_at"] != full["created_at"]
                            or not 0 <= item["position"] < full["count"]
                            or item["id"] not in {r["id"] for r in full["records"]}):
                        with lock:
                            failures.append(("shape", item, full["batch_id"]))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
