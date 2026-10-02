"""Contract tests for the optional Idempotency-Key on the sealed batch ingress.

POST /v1/encrypted-records/batch accepts an optional ``Idempotency-Key`` header.
These tests cover header validation and error precedence, first-write vs replay
(201/200) semantics, the stored-field content comparison (byte values, metadata
JSON semantics), conflict 409, tenant isolation, restart persistence, tampered
bindings (422), atomic rollback on storage failure (500) and concurrency.
"""

import base64
import copy
import json
import os
import socket
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
IDEMPOTENCY_TABLE = "encrypted_batch_idempotency_keys"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def make_config(directory: Path, active: int = 1) -> Config:
    return Config(directory / "ledger.sqlite3", active, dict(KEY_MATERIAL))


class ServerHarness:
    def __init__(self, config: Config):
        self.server = LedgerServer(("127.0.0.1", 0), config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[0], self.server.server_port
        self.base = f"http://{self.host}:{self.port}"
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


def sealed_record(record_id, algorithm="AES-256-GCM", **overrides):
    wrapped_len = 48 if algorithm == "AES-256-GCM" else 32
    record = {
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
    record.update(overrides)
    return record


class IdempotencyTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.directory = Path(self._dir.name)
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

    # -- transport helpers -------------------------------------------------

    def post(self, body, tenant="acme", key=None, key_name="Idempotency-Key"):
        headers = {"Content-Type": "application/json"}
        if tenant is not None:
            headers["X-Tenant-ID"] = tenant
        if key is not None:
            headers[key_name] = key
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.harness.base + INGEST_PATH, data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read())

    def raw_post(self, header_lines, body_obj, tenant="acme"):
        """Send a request with arbitrary raw header lines (dup/empty headers)."""
        if tenant is not None:
            header_lines = [f"X-Tenant-ID: {tenant}"] + header_lines
        payload = json.dumps(body_obj).encode("utf-8")
        request_lines = [
            f"POST {INGEST_PATH} HTTP/1.1",
            f"Host: {self.harness.host}",
            "Content-Type: application/json",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            *header_lines,
            "",
            "",
        ]
        raw = "\r\n".join(request_lines).encode("ascii") + payload
        with socket.create_connection((self.harness.host, self.harness.port)) as sock:
            sock.sendall(raw)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        head, _, body = response.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n", 1)[0].split()[1])
        return status, json.loads(body)

    def ingest(self, records, key=None, tenant="acme", key_name="Idempotency-Key"):
        return self.post({"records": records}, tenant=tenant, key=key, key_name=key_name)

    def db(self):
        return connect(self.directory / "ledger.sqlite3")

    def table_counts(self, raw):
        return {
            "batches": raw.execute("SELECT COUNT(*) FROM encrypted_batches").fetchone()[0],
            "records": raw.execute("SELECT COUNT(*) FROM encrypted_records").fetchone()[0],
            "events": raw.execute("SELECT COUNT(*) FROM encrypted_record_events").fetchone()[0],
            "keys": raw.execute(f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE}").fetchone()[0],
        }

    # -- header validation -------------------------------------------------

    def test_absent_header_preserves_legacy_201_then_400_on_id_collision(self):
        self.assertEqual(self.ingest([sealed_record("a")])[0], 201)
        # Without a key the normal existing-id rule applies (no replay).
        self.assertEqual(self.ingest([sealed_record("a")])[0], 400)

    def test_new_key_returns_201_and_persists_binding(self):
        status, body = self.ingest([sealed_record("a")], key="order-123")
        self.assertEqual(status, 201)
        raw = self.db()
        try:
            row = raw.execute(
                f"SELECT tenant, idempotency_key, batch_id FROM {IDEMPOTENCY_TABLE}"
            ).fetchone()
        finally:
            raw.close()
        self.assertEqual(tuple(row), ("acme", "order-123", body["batch_id"]))

    def test_key_length_boundaries_accepted(self):
        record = sealed_record("a")
        self.assertEqual(self.ingest([record], key="a")[0], 201)
        record_b = sealed_record("b")
        self.assertEqual(self.ingest([record_b], key="k" * 64)[0], 201)

    def test_empty_illegal_and_oversized_key_are_invalid_batch(self):
        body = {"records": [sealed_record("a")]}
        # Sent on the wire verbatim so spaces, punctuation and empty values are
        # not normalized away by an HTTP client.
        for bad in ("", " ", "bad key", "a.b", "a/b", "a:b", "a?b", "x" * 65):
            with self.subTest(bad=bad):
                status, response = self.raw_post([f"Idempotency-Key: {bad}"], body)
                self.assertEqual(status, 400)
                self.assertEqual(response["error"], "INVALID_BATCH")
                self.assertIn("Idempotency-Key", response["message"])

    def test_empty_header_line_is_invalid_batch(self):
        status, body = self.raw_post(
            ["Idempotency-Key:"], {"records": [sealed_record("a")]}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        self.assertIn("Idempotency-Key", body["message"])

    def test_duplicate_header_is_invalid_batch(self):
        for lines in (
            ["Idempotency-Key: aaa", "Idempotency-Key: aaa"],
            ["Idempotency-Key: aaa", "Idempotency-Key: bbb"],
        ):
            with self.subTest(lines=lines):
                status, body = self.raw_post(
                    lines, {"records": [sealed_record("a")]}
                )
                self.assertEqual(status, 400)
                self.assertEqual(body["error"], "INVALID_BATCH")
                self.assertIn("Idempotency-Key", body["message"])

    def test_header_name_is_case_insensitive_but_value_is_case_sensitive(self):
        records = [sealed_record("a")]
        # Header field name is case-insensitive per HTTP; binding is created.
        self.assertEqual(self.ingest(records, key="Order-1", key_name="idempotency-key")[0], 201)
        # Same exact value replays through a differently cased header NAME.
        self.assertEqual(self.ingest(copy.deepcopy(records), key="Order-1")[0], 200)
        # The value itself is case sensitive: lowercase is a distinct key.
        self.assertEqual(
            self.ingest([sealed_record("b")], key="order-1")[0], 201
        )

    # -- error precedence --------------------------------------------------

    def test_tenant_identity_403_precedes_header_validation(self):
        body = {"records": [sealed_record("a")]}
        for tenant in (None, "bad tenant!"):
            for key in ("valid-key", "bad key!", ""):
                with self.subTest(tenant=tenant, key=key):
                    status, response = self.post(body, tenant=tenant, key=key)
                    self.assertEqual(status, 403)
                    self.assertEqual(response["error"], "TENANT_RECORD_FORBIDDEN")

    def test_cross_tenant_claim_403_precedes_bad_header(self):
        record = sealed_record("a")
        record["tenant"] = "other"
        status, body = self.post({"records": [record]}, key="bad header!")
        self.assertEqual((status, body["error"]), (403, "TENANT_RECORD_FORBIDDEN"))

    def test_shape_validation_runs_before_header_syntax(self):
        # Both are 400 INVALID_BATCH, but the existing body-shape verdict names
        # the record location rather than the header.
        record = sealed_record("a")
        record["id"] = "bad id!"
        status, body = self.ingest([record], key="bad header!")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        self.assertIn("records[0].id", body["message"])
        self.assertNotIn("Idempotency-Key", body["message"])

    # -- replay: same key + same content -> 200, original body -------------

    def test_same_key_same_content_replays_original_body_with_200(self):
        records = [sealed_record("zeta"), sealed_record("alpha"), sealed_record("mid")]
        first_status, first = self.ingest(copy.deepcopy(records), key="k-1")
        self.assertEqual(first_status, 201)
        second_status, second = self.ingest(copy.deepcopy(records), key="k-1")
        self.assertEqual(second_status, 200)
        self.assertEqual(second, first)
        self.assertEqual([r["id"] for r in second["results"]], ["zeta", "alpha", "mid"])

    def test_replay_creates_no_batch_records_events_or_binding(self):
        records = [sealed_record("a"), sealed_record("b")]
        self.ingest(copy.deepcopy(records), key="k-1")
        self.ingest(copy.deepcopy(records), key="k-1")
        self.ingest(copy.deepcopy(records), key="k-1")
        raw = self.db()
        try:
            counts = self.table_counts(raw)
        finally:
            raw.close()
        self.assertEqual(counts, {"batches": 1, "records": 2, "events": 2, "keys": 1})

    def test_replayed_batch_is_readable_by_its_original_id(self):
        records = [sealed_record("a")]
        _, first = self.ingest(copy.deepcopy(records), key="k-1")
        status, replay = self.ingest(copy.deepcopy(records), key="k-1")
        self.assertEqual(status, 200)
        request = urllib.request.Request(
            self.harness.base
            + f"/v1/encrypted-records/batches/{first['batch_id']}",
            headers={"X-Tenant-ID": "acme"},
        )
        with urllib.request.urlopen(request) as response:
            read_back = json.loads(response.read())
        self.assertEqual(read_back["batch_id"], replay["batch_id"])
        self.assertEqual([r["id"] for r in read_back["records"]], ["a"])

    # -- content comparison semantics --------------------------------------

    def test_byte_fields_compare_decoded_base64_values(self):
        record = sealed_record("a")
        self.assertEqual(self.ingest([copy.deepcopy(record)], key="k-1")[0], 201)
        # Re-spell every padded base64 field with a non-canonical character that
        # decodes to the identical bytes (padding bits differ, bytes do not).
        alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789+/")

        def respell(value):
            if "=" not in value:
                return value
            chars = list(value)
            index = len(chars) - chars.count("=") - 1
            chars[index] = alphabet[alphabet.index(chars[index]) ^ 1]
            respelled = "".join(chars)
            assert base64.b64decode(respelled, validate=True) == base64.b64decode(value)
            return respelled

        for field in (record["envelope"], record["ciphertext"]):
            for name in list(field):
                field[name] = respell(field[name])
        self.assertEqual(self.ingest([record], key="k-1")[0], 200)

    def test_metadata_object_key_order_and_nesting_ignored(self):
        first = sealed_record("a", metadata={"a": 1, "nested": {"x": 1, "y": 2}})
        second = sealed_record("a", metadata={"nested": {"y": 2, "x": 1}, "a": 1})
        # Preserve the same byte fields; only the metadata object is reshaped.
        self._sync_bytes(first, second)
        self.assertEqual(self.ingest([first], key="k-1")[0], 201)
        self.assertEqual(self.ingest([second], key="k-1")[0], 200)

    def test_metadata_array_order_participates(self):
        first = sealed_record("a", metadata={"v": [1, 2]})
        second = sealed_record("a", metadata={"v": [2, 1]})
        self._sync_bytes(first, second)
        self.assertEqual(self.ingest([first], key="k-1")[0], 201)
        status, body = self.ingest([second], key="k-1")
        self.assertEqual((status, body), (409, {"error": "IDEMPOTENCY_CONFLICT"}))
    def test_metadata_numbers_compare_by_value_but_bool_differs_from_number(self):
        first = sealed_record("a", metadata={"n": 1})
        numeric = sealed_record("a", metadata={"n": 1.0})
        self._sync_bytes(first, numeric)
        self.assertEqual(self.ingest([first], key="knum")[0], 201)
        self.assertEqual(self.ingest([numeric], key="knum")[0], 200)

        first_b = sealed_record("b", metadata={"n": 1})
        boolean = sealed_record("b", metadata={"n": True})
        self._sync_bytes(first_b, boolean)
        self.assertEqual(self.ingest([first_b], key="kbool")[0], 201)
        self.assertEqual(
            self.ingest([boolean], key="kbool"),
            (409, {"error": "IDEMPOTENCY_CONFLICT"}),
        )

    def test_omitted_key_id_and_metadata_equivalent_to_null(self):
        record = sealed_record("a")
        del record["key_id"]
        del record["metadata"]
        self.assertEqual(self.ingest([copy.deepcopy(record)], key="k-1")[0], 201)
        replay = copy.deepcopy(record)
        replay["key_id"] = None
        replay["metadata"] = None
        self.assertEqual(self.ingest([replay], key="k-1")[0], 200)

    def test_ignored_fields_do_not_participate_in_comparison(self):
        record = sealed_record("a")
        self.assertEqual(self.ingest([copy.deepcopy(record)], key="k-1")[0], 201)
        # Extra per-record and envelope-level fields are ignored on write.
        replay = copy.deepcopy(record)
        replay["debug_note"] = {"anything": "ignored"}
        status, _ = self.post(
            {"records": [replay], "request_trace": "also-ignored"}, key="k-1"
        )
        self.assertEqual(status, 200)

    def test_json_whitespace_and_request_formatting_do_not_matter(self):
        record = sealed_record("a")
        self.assertEqual(self.ingest([copy.deepcopy(record)], key="k-1")[0], 201)
        # Hand-crafted pretty-printed body with reordered top-level keys.
        raw_body = json.dumps({"records": [record]}, indent=2)
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": "acme",
            "Idempotency-Key": "k-1",
        }
        request = urllib.request.Request(
            self.harness.base + INGEST_PATH,
            data=raw_body.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)

    # -- conflict: same key + different content -> 409 ---------------------

    def test_changed_ciphertext_byte_is_conflict(self):
        first = sealed_record("a")
        self.assertEqual(self.ingest([first], key="k-1")[0], 201)
        changed = copy.deepcopy(first)
        decoded = bytearray(base64.b64decode(changed["ciphertext"]["data"]))
        decoded[0] ^= 0xFF
        changed["ciphertext"]["data"] = b64(bytes(decoded))
        self.assertEqual(
            self.ingest([changed], key="k-1"),
            (409, {"error": "IDEMPOTENCY_CONFLICT"}),
        )

    def test_other_stored_field_changes_are_conflicts(self):
        base = sealed_record("a")
        self.assertEqual(self.ingest([copy.deepcopy(base)], key="k-1")[0], 201)
        variants = []
        v = copy.deepcopy(base); v["id"] = "other"; variants.append(("id", v))
        v = copy.deepcopy(base); v["algorithm"] = "AES-128-GCM"
        v["envelope"]["wrapped_key"] = b64(os.urandom(32)); variants.append(("alg", v))
        v = copy.deepcopy(base); v["key_id"] = "client-key-2"; variants.append(("key_id", v))
        v = copy.deepcopy(base); v["envelope"]["nonce"] = b64(os.urandom(12))
        variants.append(("nonce", v))
        v = copy.deepcopy(base); v["envelope"]["wrapped_key"] = b64(os.urandom(48))
        variants.append(("wrapped", v))
        v = copy.deepcopy(base); v["ciphertext"]["nonce"] = b64(os.urandom(12))
        variants.append(("cnonce", v))
        v = copy.deepcopy(base); v["ciphertext"]["tag"] = b64(os.urandom(16))
        variants.append(("tag", v))
        v = copy.deepcopy(base); v["metadata"] = {"source": "other"}
        variants.append(("metadata", v))
        for label, variant in variants:
            with self.subTest(label=label):
                self.assertEqual(
                    self.ingest([variant], key="k-1"),
                    (409, {"error": "IDEMPOTENCY_CONFLICT"}),
                )

    def test_record_order_and_count_participate(self):
        self.ingest(self._records_with_fixed_bytes(["a", "b"], "k-1"), key="k-1")
        # Same records, reversed order.
        self.assertEqual(
            self.ingest(self._records_with_fixed_bytes(["b", "a"], "k-1"), key="k-1"),
            (409, {"error": "IDEMPOTENCY_CONFLICT"}),
        )
        # Same first record, shorter batch.
        self.assertEqual(
            self.ingest(self._records_with_fixed_bytes(["a"], "k-1"), key="k-1"),
            (409, {"error": "IDEMPOTENCY_CONFLICT"}),
        )
        # Same content in the same order still replays.
        self.assertEqual(
            self.ingest(self._records_with_fixed_bytes(["a", "b"], "k-1"), key="k-1")[0],
            200,
        )

    def test_conflict_wins_over_existing_id_invalid_batch(self):
        # The retry keeps the same (now existing) id but changes content: the
        # idempotency verdict is 409 even though the id also already exists.
        first = sealed_record("a")
        self.assertEqual(self.ingest([first], key="k-1")[0], 201)
        changed = copy.deepcopy(first)
        changed["metadata"] = {"source": "changed"}
        self.assertEqual(
            self.ingest([changed], key="k-1"),
            (409, {"error": "IDEMPOTENCY_CONFLICT"}),
        )

    def test_conflict_does_not_write_or_rebind(self):
        first = sealed_record("a")
        _, first_body = self.ingest([first], key="k-1")
        changed = copy.deepcopy(first)
        changed["ciphertext"]["tag"] = b64(os.urandom(16))
        self.assertEqual(self.ingest([changed], key="k-1")[0], 409)
        raw = self.db()
        try:
            self.assertEqual(self.table_counts(raw),
                             {"batches": 1, "records": 1, "events": 1, "keys": 1})
            bound = raw.execute(
                f"SELECT batch_id FROM {IDEMPOTENCY_TABLE} "
                "WHERE tenant=? AND idempotency_key=?", ("acme", "k-1")
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(bound, first_body["batch_id"])

    # -- new key + existing id / duplicate id: 400 and key stays free -------

    def test_new_key_existing_id_is_invalid_batch_and_key_not_bound(self):
        self.ingest([sealed_record("a")])[0]
        status, body = self.ingest([sealed_record("a")], key="fresh-key")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "INVALID_BATCH")
        raw = self.db()
        try:
            binding = raw.execute(
                f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE} WHERE idempotency_key=?",
                ("fresh-key",),
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(binding, 0)
        # The rejected key can still be used by a genuinely new batch.
        self.assertEqual(self.ingest([sealed_record("b")], key="fresh-key")[0], 201)

    def test_in_batch_duplicate_id_does_not_bind_key(self):
        records = [sealed_record("dup"), sealed_record("dup")]
        self.assertEqual(self.ingest(records, key="k-dup")[0], 400)
        self.assertEqual(
            self.ingest([sealed_record("ok")], key="k-dup")[0], 201
        )

    # -- tenant isolation --------------------------------------------------

    def test_same_key_is_independent_per_tenant(self):
        records_a = [sealed_record("shared")]
        records_b = [sealed_record("shared")]
        first_a = self.ingest(copy.deepcopy(records_a), key="same", tenant="alpha")
        first_b = self.ingest(copy.deepcopy(records_b), key="same", tenant="beta")
        self.assertEqual((first_a[0], first_b[0]), (201, 201))
        self.assertNotEqual(first_a[1]["batch_id"], first_b[1]["batch_id"])
        # Each tenant replays its own binding, even with identical content.
        self.assertEqual(
            self.ingest(copy.deepcopy(records_a), key="same", tenant="alpha")[0], 200
        )
        self.assertEqual(
            self.ingest(copy.deepcopy(records_b), key="same", tenant="beta")[0], 200
        )
        raw = self.db()
        try:
            rows = raw.execute(
                f"SELECT tenant, batch_id FROM {IDEMPOTENCY_TABLE} "
                "WHERE idempotency_key=? ORDER BY tenant", ("same",)
            ).fetchall()
        finally:
            raw.close()
        self.assertEqual([tuple(r) for r in rows],
                         [("alpha", first_a[1]["batch_id"]),
                          ("beta", first_b[1]["batch_id"])])

    # -- persistence --------------------------------------------------------

    def test_binding_survives_restart_and_never_expires_on_replay(self):
        records = [sealed_record("a"), sealed_record("b")]
        _, first = self.ingest(copy.deepcopy(records), key="persist-1")

        self.harness.close()
        self.harness = ServerHarness(make_config(self.directory))
        self.addCleanup(self.harness.close)

        status, after = self.ingest(copy.deepcopy(records), key="persist-1")
        self.assertEqual(status, 200)
        self.assertEqual(after, first)

    def test_legacy_database_boots_and_legacy_batches_need_no_key(self):
        # A keyless batch written "in the past" has no binding row and still
        # works; the table is created lazily on startup (already exercised by
        # setUp on a fresh DB). Confirm a legacy-style batch has no key.
        _, body = self.ingest([sealed_record("legacy")])
        self.assertEqual(body["count"], 1)
        raw = self.db()
        try:
            bound = raw.execute(
                f"SELECT COUNT(*) FROM {IDEMPOTENCY_TABLE} WHERE batch_id=?",
                (body["batch_id"],),
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(bound, 0)

    # -- integrity of replayed bindings: 422 -------------------------------

    def test_replay_with_missing_batch_is_integrity_error(self):
        records = [sealed_record("a")]
        _, body = self.ingest(copy.deepcopy(records), key="k-1")
        raw = self.db()
        with raw:
            raw.execute("DELETE FROM encrypted_batches WHERE batch_id=?", (body["batch_id"],))
        raw.close()
        self.assertEqual(
            self.ingest(copy.deepcopy(records), key="k-1"),
            (422, {"error": "integrity_error"}),
        )

    def test_replay_with_cross_tenant_bound_batch_is_integrity_error(self):
        alpha_records = [sealed_record("a")]
        beta_records = [sealed_record("a")]
        _, alpha = self.ingest(copy.deepcopy(alpha_records), key="k-1", tenant="alpha")
        _, beta = self.ingest(copy.deepcopy(beta_records), key="k-1", tenant="beta")
        raw = self.db()
        with raw:
            # Repoint alpha's binding at beta's batch without touching beta.
            raw.execute(
                f"UPDATE {IDEMPOTENCY_TABLE} SET batch_id=? "
                "WHERE tenant='alpha' AND idempotency_key='k-1'",
                (beta["batch_id"],),
            )
        raw.close()
        self.assertEqual(
            self.ingest(copy.deepcopy(alpha_records), key="k-1", tenant="alpha"),
            (422, {"error": "integrity_error"}),
        )
        # Beta's own binding remains intact.
        self.assertEqual(
            self.ingest(copy.deepcopy(beta_records), key="k-1", tenant="beta")[0], 200
        )
        # Keep alpha's original batch referenced for clarity.
        self.assertTrue(alpha["batch_id"])

    def test_replay_failing_batch_consistency_review_is_integrity_error(self):
        records = [sealed_record("a"), sealed_record("b")]
        _, body = self.ingest(copy.deepcopy(records), key="k-1")
        raw = self.db()
        with raw:
            raw.execute(
                "UPDATE encrypted_batches SET record_count=1 WHERE batch_id=?",
                (body["batch_id"],),
            )
        raw.close()
        self.assertEqual(
            self.ingest(copy.deepcopy(records), key="k-1"),
            (422, {"error": "integrity_error"}),
        )

    # -- atomicity / storage failures: 500 ---------------------------------

    def test_storage_failure_leaves_key_unbound_and_nothing_partial(self):
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                "BEGIN SELECT RAISE(ABORT, 'inserts disabled'); END"
            )
        raw.close()
        status, body = self.ingest([sealed_record("a"), sealed_record("b")], key="k-1")
        self.assertEqual((status, body), (500, {"error": "BATCH_WRITE_FAILED"}))
        raw = self.db()
        try:
            self.assertEqual(self.table_counts(raw),
                             {"batches": 0, "records": 0, "events": 0, "keys": 0})
        finally:
            raw.close()

    def test_idempotency_insert_failure_rolls_back_the_whole_batch(self):
        raw = self.db()
        with raw:
            raw.execute(
                f"CREATE TRIGGER block_idem BEFORE INSERT ON {IDEMPOTENCY_TABLE} "
                "BEGIN SELECT RAISE(ABORT, 'no idempotency'); END"
            )
        raw.close()
        status, _ = self.ingest([sealed_record("a")], key="k-1")
        self.assertEqual(status, 500)
        raw = self.db()
        try:
            self.assertEqual(self.table_counts(raw),
                             {"batches": 0, "records": 0, "events": 0, "keys": 0})
            with raw:
                raw.execute("DROP TRIGGER block_idem")
        finally:
            raw.close()
        # Recovery: the same key is still free and the retry fully commits.
        self.assertEqual(self.ingest([sealed_record("a")], key="k-1")[0], 201)

    def test_idempotency_lookup_sqlite_failure_is_batch_write_failed(self):
        records = [sealed_record("a")]
        self.ingest(copy.deepcopy(records), key="k-1")
        raw = self.db()
        with raw:
            raw.execute(f"DROP TABLE {IDEMPOTENCY_TABLE}")
        raw.close()
        self.assertEqual(
            self.ingest(copy.deepcopy(records), key="k-1"),
            (500, {"error": "BATCH_WRITE_FAILED"}),
        )

    def test_existing_binding_and_records_survive_unrelated_failure(self):
        records = [sealed_record("keep")]
        _, first = self.ingest(copy.deepcopy(records), key="k-1")
        raw = self.db()
        with raw:
            raw.execute(
                "CREATE TRIGGER block_encrypted_insert BEFORE INSERT ON encrypted_records "
                "BEGIN SELECT RAISE(ABORT, 'no'); END"
            )
        raw.close()
        self.assertEqual(self.ingest([sealed_record("nope")], key="k-2")[0], 500)
        # The previously committed binding still replays cleanly.
        status, replay = self.ingest(copy.deepcopy(records), key="k-1")
        self.assertEqual(status, 200)
        self.assertEqual(replay["batch_id"], first["batch_id"])

    # -- concurrency --------------------------------------------------------

    def test_concurrent_same_key_same_content_single_201_rest_200(self):
        records = [sealed_record(f"r{i}") for i in range(3)]
        barrier = threading.Barrier(8)
        results = []

        def submit():
            barrier.wait()
            results.append(self.ingest(copy.deepcopy(records), key="hot-key"))

        threads = [threading.Thread(target=submit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        batch_ids = {body["batch_id"] for _, body in results}
        self.assertEqual(len(batch_ids), 1)
        self.assertTrue(all(
            [r["id"] for r in body["results"]] == ["r0", "r1", "r2"]
            for _, body in results
        ))
        raw = self.db()
        try:
            self.assertEqual(self.table_counts(raw),
                             {"batches": 1, "records": 3, "events": 3, "keys": 1})
        finally:
            raw.close()

    def test_concurrent_same_key_different_content_only_committer_binds(self):
        # All threads use the same record id but distinct ciphertext bytes, so
        # the idempotency verdict must dominate the existing-id rule: exactly
        # one 201 and every loser gets 409, never 400.
        variants = []
        for i in range(8):
            record = sealed_record("shared")
            record["ciphertext"]["data"] = b64(bytes([i]) * 8)
            variants.append([record])
        barrier = threading.Barrier(8)
        results = []

        def submit(index):
            barrier.wait()
            results.append(self.ingest(copy.deepcopy(variants[index]), key="hot-key"))

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 7)
        self.assertTrue(all(
            body == {"error": "IDEMPOTENCY_CONFLICT"}
            for status, body in results if status == 409
        ))
        raw = self.db()
        try:
            self.assertEqual(self.table_counts(raw),
                             {"batches": 1, "records": 1, "events": 1, "keys": 1})
        finally:
            raw.close()

    def test_concurrent_mixed_same_and_different_content(self):
        # Commit the winner first so the key is already bound; the race is then
        # purely between replays and conflicts against that fixed binding.
        winner_content = [sealed_record("r0")]
        _, created = self.ingest(copy.deepcopy(winner_content), key="mix-key")
        same = copy.deepcopy(winner_content)
        different = []
        for tag in range(6):
            record = sealed_record("r0")
            record["ciphertext"]["tag"] = b64(bytes([tag + 1]) * 16)
            different.append([record])
        barrier = threading.Barrier(7)
        results = []

        def submit(payload):
            barrier.wait()
            results.append(self.ingest(copy.deepcopy(payload), key="mix-key"))

        payloads = [same, *different]
        threads = [threading.Thread(target=submit, args=(p,)) for p in payloads]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(200), 1)
        self.assertEqual(statuses.count(409), 6)
        replayed = [body for status, body in results if status == 200][0]
        self.assertEqual(replayed["batch_id"], created["batch_id"])

    # -- helpers ------------------------------------------------------------

    def _sync_bytes(self, first, second):
        """Copy byte/envelope/id fields so only metadata differs."""
        second["id"] = first["id"]
        second["algorithm"] = first["algorithm"]
        second["key_id"] = first["key_id"]
        second["envelope"] = copy.deepcopy(first["envelope"])
        second["ciphertext"] = copy.deepcopy(first["ciphertext"])

    def _records_with_fixed_bytes(self, ids, _key):
        # Deterministic, distinct-per-id byte fields so only order/count varies.
        def fixed(record_id, byte):
            return {
                "id": record_id,
                "algorithm": "AES-256-GCM",
                "key_id": "k",
                "envelope": {
                    "nonce": b64(bytes([byte]) * 12),
                    "wrapped_key": b64(bytes([byte]) * 48),
                },
                "ciphertext": {
                    "data": b64(bytes([byte]) * 4),
                    "nonce": b64(bytes([byte + 1]) * 12),
                    "tag": b64(bytes([byte + 2]) * 16),
                },
                "metadata": None,
            }

        mapping = {"a": fixed("a", 10), "b": fixed("b", 20)}
        return [mapping[record_id] for record_id in ids]


if __name__ == "__main__":
    unittest.main()
