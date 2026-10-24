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


AGGREGATE_TEXT = (ROOT / "rabs-cas/src/trust_evidence/aggregate.rs").read_text()
AGGREGATE_SQL = dict(re.findall(r'const (\w+)_SQL: &str = r#"(.*?)"#;', AGGREGATE_TEXT, re.S))
ATTRIBUTION_SCHEMA = """
CREATE TABLE action_generations (id_hex TEXT PRIMARY KEY, action_key TEXT NOT NULL);
CREATE TABLE action_attempts (id_hex TEXT PRIMARY KEY, generation_hex TEXT NOT NULL, worker TEXT NOT NULL);
"""
ORIGINAL_SAMPLES = "SELECT attempt_hex, passed, seq FROM verification_samples WHERE action_key = ?1 ORDER BY attempt_hex, seq"
ORIGINAL_ATTEMPTS = """
SELECT DISTINCT a.id_hex, a.worker FROM verification_samples s
JOIN action_attempts a ON a.id_hex = s.attempt_hex
JOIN action_generations g ON g.id_hex = a.generation_hex
WHERE s.action_key = ?1 AND g.action_key = ?1 ORDER BY a.id_hex
"""


def aggregate(db, action="a"):
    sample_rows = db.execute(AGGREGATE_SQL["SAMPLES"], (action,)).fetchall()
    assert len(sample_rows) == 1
    samples, adverse, invalid = sample_rows[0]
    if invalid or adverse > samples:
        raise ValueError("sample corruption")
    attempt_rows = db.execute(AGGREGATE_SQL["ATTEMPTS"], (action,)).fetchall()
    assert len(attempt_rows) == 1
    attempts, passed, workers, invalid = attempt_rows[0]
    if invalid or not 0 <= workers <= passed <= attempts <= samples:
        raise ValueError("attribution corruption")
    return attempts, passed, workers, adverse


def original_evidence(db, action="a"):
    # Exact original row reads, followed by an independent model of the old
    # Rust decoder/reduction. No new SQL aggregate is used to derive the oracle.
    samples = db.execute(ORIGINAL_SAMPLES, (action,)).fetchall()
    for attempt, passed, seq in samples:
        if not isinstance(attempt, str) or type(passed) is not int or passed < 0 or type(seq) is not int or seq < 0:
            raise ValueError("sample corruption")
    attempts = {}
    for attempt, worker in db.execute(ORIGINAL_ATTEMPTS, (action,)):
        if not isinstance(attempt, str) or not isinstance(worker, str):
            raise ValueError("attribution corruption")
        if worker:
            attempts[attempt] = [worker, True]
    for attempt, passed, _ in samples:
        if attempt in attempts:
            attempts[attempt][1] &= passed != 0
    workers = {worker for worker, passed in attempts.values() if passed}
    return len(attempts), sum(passed for _, passed in attempts.values()), len(workers), sum(passed == 0 for _, passed, _ in samples)


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.db = database()
        self.db.executescript(ATTRIBUTION_SCHEMA)
        self.db.executemany("INSERT INTO action_generations VALUES(?,?)", [("1", "a"), ("2", "b")])
        self.db.executemany("INSERT INTO action_attempts VALUES(?,?,?)", [
            ("1", "1", "worker-a"), ("2", "1", "worker-a"),
            ("3", "1", "worker-b"), ("4", "1", ""), ("5", "2", "foreign")])

    def tearDown(self):
        self.db.close()

    def assert_parity(self):
        before = list(self.db.iterdump())
        for key in ("a", "b", "unknown"):
            self.assertEqual(aggregate(self.db, key), original_evidence(self.db, key), key)
        self.assertEqual(list(self.db.iterdump()), before)

    def test_empty_unknown_and_foreign_actions_do_not_invent_evidence(self):
        self.assert_parity()
        for n, identity in enumerate(["5", "unknown", "4"]):
            self.db.execute("INSERT INTO verification_samples VALUES('a',?,1,?)", (identity, n))
        self.assertEqual(aggregate(self.db), (0, 0, 0, 0))
        self.assert_parity()

    def test_failure_dominance_worker_counts_and_duplicates_match_each_step(self):
        history = [("1",1), ("1",1), ("2",1), ("3",1), ("4",1),
                   ("5",1), ("unknown",1), ("unknown",0), ("1",0), ("1",1), ("5",0)]
        for seq, (identity, passed) in enumerate(history):
            self.db.execute("INSERT INTO verification_samples VALUES('a',?,?,?)", (identity, passed, seq))
            self.assert_parity()
        self.assertEqual(aggregate(self.db), (3, 2, 2, 3))

    def test_unknown_corrupt_samples_are_not_filtered_out_by_a_join(self):
        self.db.execute("INSERT INTO verification_samples VALUES('a','unknown',1,1)")
        for column, value in [("passed",-1), ("passed","bad"), ("passed",0.5),
                              ("seq",-1), ("seq","bad"), ("seq",0.5), ("attempt_hex", b"bad")]:
            self.db.execute("UPDATE verification_samples SET attempt_hex='unknown',passed=1,seq=1")
            self.db.execute("UPDATE verification_samples SET " + column + "=?", (value,))
            with self.assertRaises(ValueError):
                original_evidence(self.db)
            with self.assertRaises(ValueError):
                aggregate(self.db)

    def test_nonzero_integer_decoder_contract_is_unchanged(self):
        self.db.execute("INSERT INTO verification_samples VALUES('a','1',1,1)")
        for flag in (0,1,2,9223372036854775807):
            self.db.execute("UPDATE verification_samples SET passed=?", (flag,))
            self.assert_parity()
            self.assertEqual(aggregate(self.db)[1], int(flag != 0))

    def test_malformed_worker_still_refuses(self):
        self.db.execute("INSERT INTO verification_samples VALUES('a','1',1,1)")
        self.db.execute("UPDATE action_attempts SET worker=X'FF' WHERE id_hex='1'")
        with self.assertRaises(ValueError):
            original_evidence(self.db)
        with self.assertRaises(ValueError):
            aggregate(self.db)

    def test_new_negative_evidence_and_late_attribution_are_read_afresh(self):
        self.db.execute("INSERT INTO verification_samples VALUES('a','late',1,1)")
        self.assertEqual(aggregate(self.db), (0,0,0,0))
        self.db.execute("INSERT INTO action_attempts VALUES('late','1','late-worker')")
        self.assertEqual(aggregate(self.db), (1,1,1,0))
        self.db.execute("INSERT INTO verification_samples VALUES('a','late',0,2)")
        self.assertEqual(aggregate(self.db), (1,0,0,1))
        self.assert_parity()

    def test_seeded_histories_match_the_original_reducer(self):
        for seed in range(100):
            db = database()
            db.executescript(ATTRIBUTION_SCHEMA)
            rng = random.Random(seed)
            db.executemany("INSERT INTO action_generations VALUES(?,?)", [("1","a"),("2","b")])
            for n in range(25):
                db.execute("INSERT INTO action_attempts VALUES(?,?,?)", (str(n),rng.choice(["1","2","missing"]),rng.choice(["","a","b","c"])))
            for seq in range(250):
                db.execute("INSERT INTO verification_samples VALUES(?,?,?,?)", (rng.choice(["a","b"]), str(rng.randrange(30)), rng.choice([0,1,1,1,2]),seq))
            for key in ("a","b","unknown"):
                self.assertEqual(aggregate(db,key), original_evidence(db,key), (seed,key))
            db.close()

    def test_large_history_returns_two_scalar_rows_not_samples(self):
        self.db.execute("BEGIN")
        self.db.executemany("INSERT INTO verification_samples VALUES('a','1',1,?)", ((n,) for n in range(100000)))
        self.db.execute("COMMIT")
        self.assertEqual(aggregate(self.db), (1,1,1,0))
        for sql in AGGREGATE_SQL.values():
            self.assertEqual(len(self.db.execute(sql, ("a",)).fetchall()), 1)
        self.assertEqual(aggregate(self.db), original_evidence(self.db))


def aggregate_benchmark(destination):
    # Returned-row and Python allocation comparison of exact SQL workloads,
    # not a measurement of Rust allocator bytes or end-to-end build latency.
    import gc
    import tracemalloc
    db = database()
    db.executescript(ATTRIBUTION_SCHEMA)
    db.execute("INSERT INTO action_generations VALUES('generation','a')")
    db.execute("BEGIN")
    db.executemany("INSERT INTO action_attempts VALUES(?,'generation',?)", ((str(n), 'w'+str(n%16)) for n in range(20000)))
    db.executemany("INSERT INTO verification_samples VALUES('a',?,1,?)", ((str(n%20000),n) for n in range(100000)))
    db.execute("COMMIT")
    def measure(read):
        gc.collect()
        tracemalloc.start()
        start = time.perf_counter_ns()
        answer = read(db)
        elapsed = time.perf_counter_ns()-start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return answer, {"elapsed_ns":elapsed, "python_peak_bytes":peak}
    before = measure(original_evidence)
    after = measure(aggregate)
    assert before[0] == after[0] == (20000,20000,16,0)
    record = {"scope":"native SQLite plus independent Python decoder; not Rust/Cargo/fleet", "samples":100000, "attempts":20000,
              "incumbent":dict(before[1],returned_rows=120000), "aggregate":dict(after[1],returned_rows=2), "evidence_counts":after[0]}
    Path(destination).write_text(json.dumps(record,indent=2)+"\n")
    db.close()


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
