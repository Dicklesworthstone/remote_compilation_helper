"""Native SQLite checks of production evidence-query SQL, not a Rust test.

The schema below projects the exact columns used by the queries. All index
statements and new predicates are extracted from the authored Rust files.
No synthetic comparison here counts toward deployed SPRT qualification.
"""
import hashlib
import json
from pathlib import Path
import random
import re
import sqlite3
import statistics
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
QUARANTINE = (ROOT / "rabs-cas/src/serving_sample_gate/class_quarantine.rs").read_text()
INDEX_SOURCE = (ROOT / "rabs-cas/src/read_indexes.rs").read_text()
SQL = dict(re.findall(r'const (\w+)_SQL: &str = r#"(.*?)"#;', QUARANTINE, re.S))
INDEXES = re.findall(r'const \w+_INDEX: &str = "([^"]+)";', INDEX_SOURCE)
CLASS_KIND = "rabs-live-action-class-v1"
CLASS = "rustc-dependency-compile"
PARAMETERS = (CLASS_KIND, CLASS)
SCHEMA = """
CREATE TABLE verification_samples (
 action_key TEXT NOT NULL, attempt_hex TEXT NOT NULL,
 passed INTEGER NOT NULL, seq INTEGER NOT NULL,
 PRIMARY KEY(action_key,attempt_hex,seq));
CREATE TABLE decision_receipts (
 kind TEXT NOT NULL, subject TEXT NOT NULL, seq INTEGER NOT NULL,
 decision TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY(kind,subject,seq));
CREATE TABLE action_serving_states (
 action_key TEXT PRIMARY KEY, disposition TEXT NOT NULL);
CREATE TABLE quarantines (
 scope TEXT NOT NULL, subject TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY(scope,subject));
CREATE TABLE divergence_incidents (
 action_key TEXT NOT NULL, seq INTEGER NOT NULL,
 PRIMARY KEY(action_key,seq));
"""


def database(path=":memory:"):
    db = sqlite3.connect(path, isolation_level=None)
    db.executescript(SCHEMA)
    return db


def install(db, fail_at=None):
    # Model only transaction boundaries. The executed CREATE INDEX statements
    # are the production statements, not separately maintained test indexes.
    db.execute("BEGIN IMMEDIATE")
    try:
        for position, statement in enumerate(INDEXES):
            if position == fail_at:
                raise RuntimeError("injected index DDL failure")
            db.execute(statement)
        if fail_at == len(INDEXES):
            raise RuntimeError("injected commit failure")
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def bind(db, action, classification=CLASS, seq=0, kind=CLASS_KIND):
    db.execute("INSERT OR REPLACE INTO decision_receipts VALUES(?,?,?,?,?)",
               (kind, action, seq, classification, "fixture"))


def verdict(db):
    for category in ("INCIDENT", "ADVERSE", "QUARANTINE", "DISPOSITION"):
        rows = db.execute(SQL[category], PARAMETERS).fetchall()
        if rows:
            return category, rows[0][0]
    return None


def fingerprint(db):
    digest = hashlib.sha256()
    for table in ("verification_samples", "decision_receipts", "action_serving_states",
                  "quarantines", "divergence_incidents"):
        for row in db.execute("SELECT * FROM " + table + " ORDER BY 1,2"):
            digest.update(repr((table, row)).encode())
    return digest.hexdigest()


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.db = database()
        bind(self.db, "healthy")
        bind(self.db, "culprit")

    def tearDown(self):
        self.db.close()

    def test_profile_is_atomic_idempotent_and_preserves_data(self):
        self.db.execute("INSERT INTO verification_samples VALUES('culprit','unknown',0,1)")
        before = fingerprint(self.db)
        for boundary in range(len(INDEXES) + 1):
            with self.assertRaises(RuntimeError):
                install(self.db, boundary)
            found = self.db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'idx_rabs_%'").fetchall()
            self.assertEqual(found, [])
            self.assertEqual(fingerprint(self.db), before)
        install(self.db)
        install(self.db)
        self.assertEqual(fingerprint(self.db), before)
        self.assertEqual(verdict(self.db), ("ADVERSE", "culprit"))

    def test_failed_begin_does_not_rollback_callers_transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        bind(self.db, "owned")
        with self.assertRaises(sqlite3.OperationalError):
            install(self.db)
        self.db.execute("COMMIT")
        self.assertEqual(self.db.execute("SELECT subject FROM decision_receipts WHERE subject='owned'").fetchall(), [("owned",)])

    def test_every_non_one_flag_preserves_the_original_veto(self):
        install(self.db)
        original = SQL["ADVERSE"].replace("(v.passed < 1 OR v.passed > 1)", "v.passed != 1")
        for value in (-9223372036854775808, -1, 0, 1, 2, 9223372036854775807, "bad", 0.5, b"bad"):
            self.db.execute("INSERT OR REPLACE INTO verification_samples VALUES('culprit','unknown',?,1)", (value,))
            expected = self.db.execute(original, PARAMETERS).fetchall()
            self.assertEqual(self.db.execute(SQL["ADVERSE"], PARAMETERS).fetchall(), expected, repr(value))

    def test_negative_evidence_is_not_cached_across_queries(self):
        install(self.db)
        self.assertIsNone(verdict(self.db))
        self.db.execute("INSERT INTO verification_samples VALUES('culprit','unknown',0,1)")
        self.assertEqual(verdict(self.db), ("ADVERSE", "culprit"))
        for n in range(2, 100):
            self.db.execute("INSERT INTO verification_samples VALUES('culprit',?,1,?)", (str(n), n))
        self.assertEqual(verdict(self.db), ("ADVERSE", "culprit"))

    def test_class_binding_not_risk_claims_controls_membership(self):
        install(self.db)
        bind(self.db, "private", "private-only")
        bind(self.db, "wrong-seq", seq=1)
        bind(self.db, "wrong-kind", kind="untrusted-class")
        for action in ("private", "wrong-seq", "wrong-kind", "unknown"):
            self.db.execute("INSERT INTO verification_samples VALUES(?, 'unknown',0,1)", (action,))
        self.assertIsNone(verdict(self.db))
        bind(self.db, "unknown")
        self.assertEqual(verdict(self.db), ("ADVERSE", "unknown"))

    def test_early_quarantine_and_incident_precedence_are_preserved(self):
        install(self.db)
        self.db.execute("INSERT INTO action_serving_states VALUES('culprit','presentation-quarantined')")
        self.assertEqual(verdict(self.db), ("DISPOSITION", "culprit"))
        self.db.execute("INSERT INTO quarantines VALUES('action-entry','culprit','keep')")
        self.assertEqual(verdict(self.db), ("QUARANTINE", "culprit"))
        self.db.execute("INSERT INTO verification_samples VALUES('culprit','unknown',0,1)")
        self.assertEqual(verdict(self.db), ("ADVERSE", "culprit"))
        self.db.execute("INSERT INTO divergence_incidents VALUES('culprit',1)")
        self.assertEqual(verdict(self.db), ("INCIDENT", "culprit"))

    def test_indexed_state_updates_are_visible_and_other_quarantines_do_not_demote(self):
        install(self.db)
        self.db.execute("INSERT INTO action_serving_states VALUES('culprit','servable')")
        for scope in ("logical-object", "location"):
            self.db.execute("INSERT INTO quarantines VALUES(?,'culprit','keep')", (scope,))
        self.assertIsNone(verdict(self.db))
        for disposition in ("quarantined", "presentation-quarantined"):
            self.db.execute("UPDATE action_serving_states SET disposition=?", (disposition,))
            self.assertEqual(verdict(self.db), ("DISPOSITION", "culprit"))

    def test_existing_data_and_indexes_survive_reopening(self):
        directory = Path(tempfile.mkdtemp(prefix="rabs-query-reopen-"))
        path = directory / "metadata.sqlite"
        db = database(path)
        bind(db, "culprit")
        db.execute("INSERT INTO verification_samples VALUES('culprit','unknown',0,1)")
        before = fingerprint(db)
        install(db)
        db.close()
        db = sqlite3.connect(path, isolation_level=None)
        install(db)
        self.assertEqual(fingerprint(db), before)
        self.assertEqual(verdict(db), ("ADVERSE", "culprit"))
        db.close()

    def test_seeded_predicate_equivalence_with_and_without_indexes(self):
        original = SQL["ADVERSE"].replace("(v.passed < 1 OR v.passed > 1)", "v.passed != 1")
        for seed in range(80):
            db = database()
            rng = random.Random(seed)
            for n in range(30):
                bind(db, str(n), CLASS if rng.randrange(3) else "private-only")
                db.execute("INSERT INTO verification_samples VALUES(?,?,?,?)", (str(n), str(n), rng.choice([1,1,1,0,-1,2]), n))
            before = set(db.execute(original.replace("LIMIT 1", ""), PARAMETERS))
            install(db)
            after = set(db.execute(SQL["ADVERSE"].replace("LIMIT 1", ""), PARAMETERS))
            self.assertEqual(after, before, seed)
            witness = db.execute(SQL["ADVERSE"], PARAMETERS).fetchall()
            self.assertEqual(bool(witness), bool(before), seed)
            if witness:
                self.assertIn(witness[0], before)
            db.close()

    def test_healthy_history_uses_range_seeks_not_a_full_scan(self):
        install(self.db)
        adverse = " ".join(row[-1] for row in self.db.execute("EXPLAIN QUERY PLAN " + SQL["ADVERSE"], PARAMETERS))
        disposition = " ".join(row[-1] for row in self.db.execute("EXPLAIN QUERY PLAN " + SQL["DISPOSITION"], PARAMETERS))
        self.assertIn("passed<?", adverse)
        self.assertIn("passed>?", adverse)
        self.assertNotIn("SCAN v", adverse)
        self.assertIn("disposition=?", disposition)
        self.assertNotIn("SCAN s", disposition)


def benchmark(destination):
    """Compare incumbent and candidate on one unchanged native SQLite dataset."""
    db = database()
    for n in range(4096):
        bind(db, str(n))
        db.execute("INSERT INTO action_serving_states VALUES(?, 'servable')", (str(n),))
    db.execute("BEGIN")
    db.executemany("INSERT INTO verification_samples VALUES(?,?,1,?)",
                   ((str(n % 4096), f"{n:032x}", n) for n in range(250000)))
    db.execute("COMMIT")
    incumbent = SQL["ADVERSE"].replace("(v.passed < 1 OR v.passed > 1)", "v.passed != 1")
    def measure(query):
        samples = []
        for _ in range(7):
            start = time.perf_counter_ns()
            result = db.execute(query, PARAMETERS).fetchall()
            samples.append(time.perf_counter_ns() - start)
            assert not result
        steps = 0
        def tick():
            nonlocal steps
            steps += 1
            return 0
        db.set_progress_handler(tick, 1)
        db.execute(query, PARAMETERS).fetchall()
        db.set_progress_handler(None, 0)
        return {"median_ns": int(statistics.median(samples)), "vm_steps": steps}
    before = fingerprint(db)
    old = measure(incumbent)
    start = time.perf_counter_ns()
    install(db)
    build = time.perf_counter_ns() - start
    new = measure(SQL["ADVERSE"])
    assert fingerprint(db) == before
    record = {"scope": "native SQLite exact class-adverse query only; not Rust/Cargo/fleet throughput", "sqlite_version": sqlite3.sqlite_version, "positive_samples": 250000, "classes_bound": 4096, "incumbent": old, "indexed_ranges": new, "index_build_ns": build}
    Path(destination).write_text(json.dumps(record, indent=2) + "\n")
    db.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
