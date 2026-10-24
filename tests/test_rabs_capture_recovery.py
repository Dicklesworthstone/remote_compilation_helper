#!/usr/bin/env python3
"""Execute live capture recovery's literal SQL against a SQLite schema slice.

This validates SQL syntax, normalized binding predicates and scan pagination.
It does NOT execute/type-check Rust, serde, RABS hashing, scoped authorization,
CAS GC, or the repository's full migrations. Run the included Rust tests too.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import re
import random
import sqlite3
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'rabsd/src/coord/live_dependency/capture_pins/recovery/reconcile.rs'
TEXT = SOURCE.read_text()

def rust_sql(name: str) -> str:
    match = re.search(r'const ' + name + r': &str = "(.*?)";', TEXT, re.S)
    if not match:
        raise AssertionError(f'Missing production SQL: {name}')
    # These strings use Rust backslash-newline continuation, not raw strings.
    return re.sub(r'\\\n\s*', '', match.group(1))

FENCED = rust_sql('FENCED_SQL')
SCAN = rust_sql('SCAN_SQL')
CURSOR = rust_sql('CURSOR_SQL')
CLASS = 'live-dependency-capture-v1'
CURSOR_KIND = 'rabs-capture-recovery-cursor-v1'
PAGE_SIZE = 32

# Relevant tables at repository metadata schema v25. This is deliberately a
# schema slice, not a claim to have exercised the full migration implementation.
SCHEMA = '''
CREATE TABLE coordinator_authorities (
 key TEXT PRIMARY KEY, algo TEXT NOT NULL, domain TEXT NOT NULL,
 bytes BLOB NOT NULL, cluster_id TEXT NOT NULL, incarnation BLOB NOT NULL,
 term INTEGER NOT NULL, acquired_seq INTEGER NOT NULL, released INTEGER NOT NULL);
CREATE TABLE action_generations (
 id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, action_key TEXT NOT NULL,
 authority_key TEXT NOT NULL, tombstoned INTEGER NOT NULL, per_key_ordinal BLOB);
CREATE TABLE action_attempts (
 id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, generation_hex TEXT NOT NULL,
 worker TEXT NOT NULL, seq INTEGER NOT NULL, worker_boot_generation BLOB,
 worker_incarnation BLOB, execution_lease_hex TEXT);
CREATE TABLE execution_leases (
 id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, attempt_hex TEXT NOT NULL,
 renewal_seq INTEGER NOT NULL, expires_at_seq INTEGER NOT NULL, released INTEGER NOT NULL);
CREATE TABLE pins (
 id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, root_key TEXT NOT NULL,
 owner TEXT NOT NULL, class TEXT NOT NULL, expires_at_seq INTEGER,
 released INTEGER NOT NULL, evidence TEXT, renewal_seq INTEGER NOT NULL DEFAULT 0,
 durable INTEGER NOT NULL DEFAULT 1, reason TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_pins_released ON pins (released);
CREATE TABLE decision_receipts (
 kind TEXT NOT NULL, subject TEXT NOT NULL, seq INTEGER NOT NULL,
 decision TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY (kind, subject, seq));
'''

def be(value: int, width: int = 16) -> bytes:
    return value.to_bytes(width, 'big')

def params() -> list:
    return [
        'authority:prior', 'cluster', be(11), 1, f'{13:032x}', be(13),
        'action:key', be(1, 8), f'{17:032x}', be(17), 'edge-local:test',
        be(1, 8), be(23), f'{19:032x}', be(19), 0, 'authority', bytes(range(32)),
    ]

def database(path: str = ':memory:') -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    p = params()
    db.execute('INSERT INTO coordinator_authorities VALUES (?,?,?,?,?,?,?,?,?)',
        (p[0], 'sha256-v1', p[16], p[17], p[1], p[2], p[3], 1, 1))
    db.execute('INSERT INTO action_generations VALUES (?,?,?,?,?,?)',
        (p[4], p[5], p[6], p[0], 1, p[7]))
    db.execute('INSERT INTO action_attempts VALUES (?,?,?,?,?,?,?,?)',
        (p[8], p[9], p[4], p[10], 3, p[11], p[12], p[13]))
    db.execute('INSERT INTO execution_leases VALUES (?,?,?,?,?,?)',
        (p[13], p[14], p[8], 0, 1000000, 0))
    db.commit()
    return db

def bound(db: sqlite3.Connection, p=None) -> bool:
    return db.execute(FENCED, params() if p is None else p).fetchall() == [(1,)]

def pin(db, index: int, *, owner='recoverable', pin_class=CLASS,
        released=0, expires=None, durable=1, renewal=0, evidence='journal'):
    db.execute('INSERT INTO pins VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        (f'{index:032x}', be(index), f'object:{index}', owner, pin_class,
         expires, released, evidence, renewal, durable, 'fixture'))

def scan_and_release_model(db: sqlite3.Connection, limit=None) -> tuple[int, int]:
    """Model only page/cursor behavior, not the Rust witness/release policy."""
    after = ''
    released = pages = 0
    while True:
        rows = db.execute(SCAN, (CLASS, after)).fetchall()
        pages += 1
        for id_hex, owner, root, evidence, raw_id in rows:
            assert id_hex > after
            after = id_hex
            if owner == 'retain' or evidence is None:
                continue
            db.execute('UPDATE pins SET released=1 WHERE id_hex=?', (id_hex,))
            released += 1
            if limit is not None and released == limit:
                db.commit()
                return released, pages
        if len(rows) < PAGE_SIZE:
            db.commit()
            return released, pages


def cursor_page_model(db, subject='authority:current', *, crash_after=None):
    """Only a cursor/crash model. Sentinel owners stand in for Rust proof checks.

    The real witness deserializer, hashes and scoped release are covered by the
    Rust tests, not this model. SQL strings here are extracted from production.
    Each release commits before the checkpoint, matching the store API ordering.
    """
    cursor = db.execute(CURSOR, (CURSOR_KIND, subject)).fetchall()
    sequence, after = 1, ''
    if cursor:
        sequence, state, after = cursor[0]
        if not isinstance(sequence, int) or sequence <= 0 or not isinstance(after, str):
            raise ValueError('cursor shape')
        if after and not re.fullmatch('[0-9a-f]{32}', after):
            raise ValueError('cursor identity')
        if state == 'complete':
            return 0, 0, True
        if state != 'pending' or not after or sequence == 2**63 - 1:
            raise ValueError('cursor state or exhaustion')
        sequence += 1
    rows = db.execute(SCAN, (CLASS, after)).fetchall()
    assert len(rows) <= PAGE_SIZE
    released_count = 0
    if crash_after == 0:
        return len(rows), 0, False
    for id_hex, owner, root, evidence, raw_id in rows:
        if not re.fullmatch('[0-9a-f]{32}', id_hex) or id_hex <= after:
            raise ValueError('pin ordering')
        after = id_hex
        # Deliberately a sentinel, NOT a model of authorization or root hashes.
        if owner != 'recoverable' or not isinstance(evidence, str) or len(evidence.encode()) > 8192:
            continue
        db.execute('UPDATE pins SET released=1 WHERE id_hex=?', (id_hex,))
        db.commit()
        released_count += 1
        if released_count == crash_after:
            return len(rows), released_count, False
    complete = len(rows) < PAGE_SIZE
    db.execute('INSERT INTO decision_receipts VALUES (?,?,?,?,?)',
               (CURSOR_KIND, subject, sequence, 'complete' if complete else 'pending', after))
    db.commit()
    return len(rows), released_count, complete

class RecoverySqlTests(unittest.TestCase):
    def test_exact_durable_fence_accepts(self):
        with closing(database()) as db:
            self.assertTrue(bound(db))

    def test_every_normalized_binding_column_is_required(self):
        mutations = [
            ('coordinator_authorities', 'key', 'other'),
            ('coordinator_authorities', 'algo', 'sha256-unknown'),
            ('coordinator_authorities', 'domain', 'other'),
            ('coordinator_authorities', 'bytes', b'X' * 32),
            ('coordinator_authorities', 'cluster_id', 'other'),
            ('coordinator_authorities', 'incarnation', be(12)),
            ('coordinator_authorities', 'term', 2),
            ('coordinator_authorities', 'released', 0),
            ('action_generations', 'id_hex', f'{14:032x}'),
            ('action_generations', 'id', be(14)),
            ('action_generations', 'action_key', 'other'),
            ('action_generations', 'authority_key', 'other'),
            ('action_generations', 'tombstoned', 0),
            ('action_generations', 'per_key_ordinal', be(2, 8)),
            ('action_attempts', 'id_hex', f'{18:032x}'),
            ('action_attempts', 'id', be(18)),
            ('action_attempts', 'generation_hex', f'{14:032x}'),
            ('action_attempts', 'worker', 'other'),
            ('action_attempts', 'worker_boot_generation', be(2, 8)),
            ('action_attempts', 'worker_incarnation', be(24)),
            ('action_attempts', 'execution_lease_hex', f'{20:032x}'),
            ('execution_leases', 'id_hex', f'{20:032x}'),
            ('execution_leases', 'id', be(20)),
            ('execution_leases', 'attempt_hex', f'{18:032x}'),
        ]
        for table, column, value in mutations:
            with self.subTest(table=table, column=column), closing(database()) as db:
                # Identifiers come solely from the static list above.
                db.execute(f'UPDATE {table} SET {column}=?', (value,))
                self.assertFalse(bound(db))

    def test_missing_or_legacy_null_bindings_never_prove_abandonment(self):
        for table, column in [
            ('action_generations', 'per_key_ordinal'),
            ('action_attempts', 'worker_boot_generation'),
            ('action_attempts', 'worker_incarnation'),
            ('action_attempts', 'execution_lease_hex'),
        ]:
            with self.subTest(table=table, column=column), closing(database()) as db:
                db.execute(f'UPDATE {table} SET {column}=NULL')
                self.assertFalse(bound(db))
        for table in ['coordinator_authorities', 'action_generations',
                      'action_attempts', 'execution_leases']:
            with self.subTest(missing=table), closing(database()) as db:
                db.execute(f'DELETE FROM {table}')
                self.assertFalse(bound(db))

    def test_renewal_can_advance_but_never_regress(self):
        with closing(database()) as db:
            p = params()
            p[15] = 4
            self.assertFalse(bound(db, p))
            db.execute('UPDATE execution_leases SET renewal_seq=4')
            self.assertTrue(bound(db, p))
            db.execute('UPDATE execution_leases SET renewal_seq=5')
            self.assertTrue(bound(db, p))

    def test_wall_clock_and_lease_release_are_not_the_fence(self):
        for expiry in [0, 1, 2**63 - 1]:
            for released in [0, 1]:
                with self.subTest(expiry=expiry, released=released), closing(database()) as db:
                    db.execute('UPDATE execution_leases SET expires_at_seq=?, released=?',
                               (expiry, released))
                    self.assertTrue(bound(db))
                    db.execute('UPDATE action_generations SET tombstoned=0')
                    self.assertFalse(bound(db))

    def test_normalized_blob_endianness_is_significant(self):
        for parameter, value, width in [(2,11,16),(5,13,16),(7,1,8),(9,17,16),
                                      (11,1,8),(12,23,16),(14,19,16)]:
            with self.subTest(parameter=parameter), closing(database()) as db:
                p = params()
                p[parameter] = value.to_bytes(width, 'little')
                self.assertFalse(bound(db, p))

    def test_parameters_do_not_interpret_sql(self):
        with closing(database()) as db:
            p = params()
            p[1] = "'; DROP TABLE pins; --"
            self.assertFalse(bound(db, p))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM pins').fetchone(), (0,))

    def test_only_unchanged_live_capture_pin_semantics_are_scanned(self):
        with closing(database()) as db:
            pin(db, 1)
            pin(db, 2, pin_class='action-publication')
            pin(db, 3, released=1)
            pin(db, 4, expires=0)
            pin(db, 5, durable=0)
            pin(db, 6, renewal=1)
            pin(db, 7, pin_class='incident')
            self.assertEqual([r[0] for r in db.execute(SCAN, (CLASS,''))], [f'{1:032x}'])

    def test_three_pages_do_not_skip_rows_when_release_changes_scan_membership(self):
        with closing(database()) as db:
            for index in range(1, 390):
                pin(db, index, owner='retain' if index % 7 == 0 else 'recoverable')
            released, pages = scan_and_release_model(db)
            self.assertEqual(released, 389 - 389 // 7)
            self.assertGreaterEqual(pages, 4)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pins WHERE released=0 AND owner='recoverable'").fetchone(), (0,))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pins WHERE released=1 AND owner='retain'").fetchone(), (0,))
            self.assertEqual(scan_and_release_model(db)[0], 0)

    def test_interrupted_recovery_continues_after_real_sqlite_reopen(self):
        # Retain the test database for inspection; no file cleanup is performed.
        directory = tempfile.mkdtemp(prefix='rabs-capture-recovery-')
        path = str(Path(directory) / 'metadata.sqlite')
        with closing(database(path)) as db:
            for index in range(1, 300):
                pin(db, index)
            pin(db, 400, pin_class='action-publication')
            self.assertEqual(scan_and_release_model(db, limit=17)[0], 17)
        with closing(sqlite3.connect(path)) as reopened:
            self.assertEqual(scan_and_release_model(reopened)[0], 299 - 17)
            self.assertEqual(reopened.execute('SELECT released FROM pins WHERE id_hex=?',
                             (f'{400:032x}',)).fetchone(), (0,))
            self.assertEqual(scan_and_release_model(reopened)[0], 0)

    def test_cursor_survives_reopen_and_completed_history_stops_writing(self):
        directory = tempfile.mkdtemp(prefix='rabs-capture-cursor-')
        path = str(Path(directory) / 'metadata.sqlite')
        with closing(database(path)) as db:
            for index in range(1, 80):
                pin(db, index)
            self.assertEqual(cursor_page_model(db), (32, 32, False))
        with closing(sqlite3.connect(path)) as reopened:
            self.assertEqual(cursor_page_model(reopened), (32, 32, False))
            self.assertEqual(cursor_page_model(reopened), (15, 15, True))
            changes = reopened.total_changes
            self.assertEqual(cursor_page_model(reopened), (0, 0, True))
            self.assertEqual(reopened.total_changes, changes)

    def test_every_release_checkpoint_crash_cut_keeps_remaining_pins_reachable(self):
        for cut in range(PAGE_SIZE + 1):
            with self.subTest(cut=cut), closing(database()) as db:
                for index in range(1, 72):
                    pin(db, index)
                db.commit()
                scanned, released_count, complete = cursor_page_model(db, crash_after=cut)
                self.assertEqual(scanned, PAGE_SIZE)
                self.assertEqual(released_count, cut)
                self.assertFalse(complete)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM decision_receipts').fetchone(), (0,))
                total = released_count
                while not complete:
                    scanned, count, complete = cursor_page_model(db)
                    self.assertLessEqual(scanned, PAGE_SIZE)
                    total += count
                self.assertEqual(total, 71)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM pins WHERE released=0').fetchone(), (0,))

    def test_new_authority_does_not_inherit_a_completed_or_partial_cursor(self):
        with closing(database()) as db:
            db.execute('INSERT INTO decision_receipts VALUES (?,?,?,?,?)',
                       (CURSOR_KIND, 'authority:old', 10, 'complete', 'f' * 32))
            for index in range(1, 4):
                pin(db, index)
            self.assertEqual(cursor_page_model(db), (3, 3, True))

    def test_malformed_or_exhausted_checkpoints_refuse_without_mutation(self):
        for seq, state, after in [(0, 'complete', ''), (-1, 'pending', '0' * 32),
                                  (1, 'pending', ''), (1, 'unknown', '0' * 32),
                                  (1, 'complete', 'F' * 32), (1, 'complete', 'f' * 33),
                                  (2**63 - 1, 'pending', '0' * 32)]:
            with self.subTest(seq=seq, state=state, after=after), closing(database()) as db:
                pin(db, 1)
                db.execute('INSERT INTO decision_receipts VALUES (?,?,?,?,?)',
                           (CURSOR_KIND, 'authority:current', seq, state, after))
                db.commit()
                before = db.total_changes
                with self.assertRaises(ValueError):
                    cursor_page_model(db)
                self.assertEqual(db.total_changes, before)
                self.assertEqual(db.execute('SELECT released FROM pins').fetchone(), (0,))

    def test_oversized_payloads_are_bounded_in_sql_and_in_utf8_bytes(self):
        with closing(database()) as db:
            pin(db, 1, evidence='x' * 8192)
            pin(db, 2, evidence='x' * 8193)
            pin(db, 3, evidence='\U0001f600' * 8192)
            rows = db.execute(SCAN, (CLASS, '')).fetchall()
            self.assertEqual(len(rows[0][3]), 8192)
            self.assertIsNone(rows[1][3], 'oversized text must not be returned to Rust')
            self.assertGreater(len(rows[2][3].encode()), 8192)
            self.assertEqual(cursor_page_model(db), (3, 1, True))
            self.assertEqual(db.execute('SELECT released FROM pins ORDER BY id_hex').fetchall(), [(1,), (0,), (0,)])

    def test_retained_prefix_does_not_starve_later_recoverable_pages(self):
        with closing(database()) as db:
            for index in range(1, 3 * PAGE_SIZE + 8):
                pin(db, index, owner='retain' if index <= 2 * PAGE_SIZE else 'recoverable')
            counts = []
            while True:
                scanned, count, complete = cursor_page_model(db)
                counts.append(count)
                if complete:
                    break
            self.assertEqual(counts, [0, 0, 32, 7])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pins WHERE owner='retain' AND released=1").fetchone(), (0,))

    def test_fifty_seeded_mixed_histories_converge_without_releasing_controls(self):
        for seed in range(50):
            with self.subTest(seed=seed), closing(database()) as db:
                rng = random.Random(seed)
                expected = 0
                for index in range(1, 161):
                    keep = rng.randrange(4) == 0
                    pin(db, index, owner='retain' if keep else 'recoverable')
                    expected += not keep
                complete = False
                total = 0
                while not complete:
                    scanned, count, complete = cursor_page_model(db)
                    self.assertLessEqual(scanned, PAGE_SIZE)
                    total += count
                self.assertEqual(total, expected)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM pins WHERE owner='retain' AND released=1").fetchone(), (0,))

    def test_cursor_lookup_uses_authority_prefix_index(self):
        with closing(database()) as db:
            plan = '\n'.join(row[3] for row in db.execute('EXPLAIN QUERY PLAN ' + CURSOR,
                                                       (CURSOR_KIND, 'authority:current')))
            self.assertIn('INDEX', plan)
            self.assertIn('kind=? AND subject=?', plan)

if __name__ == '__main__':
    unittest.main(verbosity=2)
