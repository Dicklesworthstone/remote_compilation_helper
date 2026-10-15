"""Native SQLite checks of the SQL embedded in the Rust SPRT implementation.

The fixture schema projects only the columns those queries use. The small
Python reducer is a crash-ordering model, NOT execution of the Rust reducer,
FrankenSQLite, rustc, or a Cargo cache hit. Rust regressions remain mandatory.
"""

from decimal import Decimal, localcontext, ROUND_CEILING
from pathlib import Path
import random
import re
import sqlite3
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "rabs-cas/src/serving_sample_gate/sprt_ladder.rs"
TEXT = SOURCE.read_text()
SQL = dict(re.findall(r'const (\w+)_SQL: &str = r#"(.*?)"#;', TEXT, re.S))
CONSTANTS = dict(re.findall(r'const (\w+): &str = "([^"]*)";', TEXT))
STEP = int(re.search(r'const PASSES_PER_STEP: u64 = ([0-9_]+);', TEXT)[1].replace("_", ""))
PAGE = int(re.search(r'const PAGE: usize = ([0-9_]+);', TEXT)[1].replace("_", ""))
FINAL = STEP * 3


class Fixture:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS decision_receipts (
          kind TEXT NOT NULL, subject TEXT NOT NULL, seq INTEGER NOT NULL,
          decision TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(kind,subject,seq));
        CREATE TABLE IF NOT EXISTS action_generations (id_hex TEXT PRIMARY KEY, action_key TEXT);
        CREATE TABLE IF NOT EXISTS action_attempts (
          id_hex TEXT PRIMARY KEY, generation_hex TEXT, worker TEXT NOT NULL DEFAULT 'fixture-worker');
        CREATE TABLE IF NOT EXISTS verification_samples (
          action_key TEXT, attempt_hex TEXT, passed INTEGER, seq INTEGER,
          PRIMARY KEY(action_key,attempt_hex,seq));
        CREATE TABLE IF NOT EXISTS action_publications (
          action_key TEXT PRIMARY KEY, winner_attempt_hex TEXT, manifest_key TEXT);
        """)

    def record(self, kind, subject, seq, decision, reason):
        self.db.execute("INSERT OR REPLACE INTO decision_receipts VALUES(?,?,?,?,?)",
                        (kind, subject, seq, decision, reason))
        self.db.commit()

    def receipt(self, kind, subject, seq=0):
        return self.db.execute(SQL["RECEIPT"], (kind, subject, seq)).fetchone()

    def bind(self, action="a", classification=None):
        classification = CONSTANTS["CLASS"] if classification is None else classification
        self.db.execute("INSERT INTO action_generations VALUES(?,?)", (action, action))
        self.db.execute("INSERT INTO action_publications VALUES(?,?,?)",
                        (action, f"{0:032x}", "manifest-" + action))
        self.db.execute("INSERT OR IGNORE INTO action_attempts(id_hex,generation_hex) VALUES(?,?)", (f"{0:032x}", action))
        self.record(CONSTANTS["CLASS_KIND"], action, 0, classification, "fixture")

    def proof(self, attempt, seq=None, action="a", receipt=True, passed=1, generation=None, manifest=None):
        seq = attempt if seq is None else seq
        identity = f"{attempt:032x}"
        self.db.execute("INSERT OR IGNORE INTO action_attempts(id_hex,generation_hex) VALUES(?,?)", (identity, generation or action))
        self.db.execute("INSERT OR REPLACE INTO verification_samples VALUES(?,?,?,?)",
                        (action, identity, passed, seq))
        self.db.commit()
        if receipt:
            self.record(CONSTANTS["VERIFIED"], action, seq, identity, manifest or "manifest-" + action)

    def state(self):
        row = self.receipt(CONSTANTS["STATE"], CONSTANTS["CLASS"])
        if row is None:
            return 0, 0
        passes, cursor = map(int, row)
        if row != (str(passes), str(cursor)) or not 0 <= passes <= FINAL or not passes <= cursor <= 2**63 - 1:
            raise ValueError("invalid checkpoint")
        return passes, cursor

    def save(self, passes, cursor):
        self.record(CONSTANTS["STATE"], CONSTANTS["CLASS"], 0, str(passes), str(cursor))

    def admitted(self, action, seq, attempt, manifest):
        expected = self.db.execute("SELECT manifest_key FROM action_publications WHERE action_key=?", (action,)).fetchone()
        if seq < 0 or re.fullmatch("[0-9a-f]{32}", attempt) is None or expected != (manifest,):
            return False
        return bool(self.db.execute(SQL["ATTRIBUTED"],
            (attempt, action, seq, CONSTANTS["CLASS_KIND"], CONSTANTS["CLASS"])).fetchone())

    def fold(self, crash_after_markers=None):
        passes, cursor = self.state()
        original = passes, cursor
        if passes == FINAL:
            return passes, cursor
        rows = self.db.execute(SQL["PAGE"], (CONSTANTS["VERIFIED"], cursor)).fetchall()
        assert len(rows) <= PAGE
        external = False
        markers = 0
        for position, kind, action, seq, attempt, manifest in rows:
            assert position > cursor
            cursor = position
            external |= kind not in (CONSTANTS["STATE"], CONSTANTS["COUNTED"], CONSTANTS["PROMOTION"])
            if kind != CONSTANTS["VERIFIED"] or not self.admitted(action, seq, attempt, manifest):
                continue
            subject = action + ":" + attempt
            marker = self.receipt(CONSTANTS["COUNTED"], subject)
            if marker is not None:
                if marker != ("consumed", CONSTANTS["CLASS"]):
                    raise ValueError("conflicting marker")
                continue
            self.record(CONSTANTS["COUNTED"], subject, 0, "consumed", CONSTANTS["CLASS"])
            markers += 1
            if markers == crash_after_markers:
                raise RuntimeError("modeled interruption after durable marker, before checkpoint")
            passes += 1
            if passes == FINAL:
                break
        if (passes, cursor) != original and (external or len(rows) == PAGE):
            self.save(passes, cursor)
        return passes, cursor

    def drain(self):
        previous = None
        for _ in range(20000):
            value = self.fold()
            if value == previous:
                return value
            previous = value
        raise AssertionError("journal failed to settle")


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.f.bind()

    def tearDown(self):
        self.f.db.close()

    def test_sprt_threshold_matches_high_precision_likelihood_boundary(self):
        with localcontext() as context:
            context.prec = 80
            p0, p1, alpha, beta = map(Decimal, ("0.000001", "0.0001", "0.001", "0.001"))
            increment = ((1 - p1) / (1 - p0)).ln()
            boundary = (beta / (1 - alpha)).ln()
            expected = int((boundary / increment).to_integral_value(rounding=ROUND_CEILING))
            self.assertEqual(STEP, expected)
            self.assertEqual(STEP, 69762)
            self.assertGreater((STEP - 1) * increment, boundary)
            self.assertLess(STEP * increment, boundary)
            self.assertLess(abs(STEP * increment - Decimal("-6.906786798374720935")), Decimal("1e-18"))

    def test_every_ladder_boundary_uses_new_trials_and_nonzero_verification(self):
        for count in range(FINAL + 1):
            phase = min(count // STEP, 3)
            rate = (10000, 2500, 500, 100)[phase]
            quota = (0, 3, 19, 99)[phase]
            self.assertEqual((quota + 1) * rate, 10000)
        self.assertEqual(FINAL, 209286)

    def test_all_three_promotions_require_distinct_attributed_journal_proofs(self):
        # Seed full synthetic relational proofs, NOT a credited checkpoint.
        # Every item must pass the exact production SQL and consume its own
        # marker through the reducer model before reaching a crossing.
        first = 1
        for boundary in (STEP - 1, STEP, 2 * STEP - 1, 2 * STEP, FINAL - 1, FINAL):
            proofs = [(f"{number:032x}", number) for number in range(first, boundary + 1)]
            self.f.db.executemany(
                "INSERT INTO action_attempts(id_hex,generation_hex) VALUES(?,?)",
                ((identity, "a") for identity, _ in proofs),
            )
            self.f.db.executemany(
                "INSERT INTO verification_samples VALUES(?,?,?,?)",
                (("a", identity, 1, seq) for identity, seq in proofs),
            )
            self.f.db.executemany(
                "INSERT INTO decision_receipts VALUES(?,?,?,?,?)",
                ((CONSTANTS["VERIFIED"], "a", seq, identity, "manifest-a")
                 for identity, seq in proofs),
            )
            self.f.db.commit()
            self.assertEqual(self.f.drain()[0], boundary)
            markers = self.f.db.execute(
                "SELECT COUNT(*) FROM decision_receipts WHERE kind=?",
                (CONSTANTS["COUNTED"],),
            ).fetchone()[0]
            self.assertEqual(markers, boundary)
            first = boundary + 1
        self.assertEqual(self.f.state()[0], FINAL)

    def test_page_is_rowid_range_scan_not_history_sort(self):
        plan = self.f.db.execute("EXPLAIN QUERY PLAN " + SQL["PAGE"], (CONSTANTS["VERIFIED"], 0)).fetchall()
        descriptions = " ".join(row[-1] for row in plan)
        self.assertIn("INTEGER PRIMARY KEY", descriptions)
        self.assertNotIn("TEMP B-TREE", descriptions)

    def test_bounded_pages_do_not_load_unrelated_large_receipt_payloads(self):
        for n in range(PAGE + 20):
            self.f.record("unrelated", str(n), 0, "x" * 10000, "y" * 10000)
        rows = self.f.db.execute(SQL["PAGE"], (CONSTANTS["VERIFIED"], 0)).fetchall()
        self.assertEqual(len(rows), PAGE)
        self.assertTrue(all(row[2:] == (None, None, None, None) for row in rows))
        self.f.proof(1)
        self.assertEqual(self.f.drain()[0], 1)

    def test_raw_samples_winner_unknown_attempt_and_wrong_manifest_do_not_count(self):
        self.f.proof(1, receipt=False)
        self.f.proof(0, seq=2)
        self.f.record(CONSTANTS["VERIFIED"], "a", 3, f"{999:032x}", "manifest-a")
        self.f.proof(4, manifest="wrong")
        self.assertEqual(self.f.drain()[0], 0)
        self.f.proof(5)
        self.assertEqual(self.f.drain()[0], 1)

    def test_private_class_and_foreign_generation_do_not_count(self):
        self.f.bind("b", "private-only")
        self.f.proof(1, action="b")
        self.f.proof(2, generation="b", action="a")
        self.assertEqual(self.f.drain()[0], 0)

    def test_empty_worker_does_not_count_as_an_attributable_comparison(self):
        self.f.proof(1)
        self.f.db.execute("UPDATE action_attempts SET worker='' WHERE id_hex=?", (f"{1:032x}",))
        self.f.db.commit()
        self.assertEqual(self.f.drain()[0], 0)
        self.f.proof(2)
        self.assertEqual(self.f.drain()[0], 1)

    def test_repeated_samples_receipts_and_rowid_churn_cannot_double_count(self):
        self.f.proof(1)
        self.assertEqual(self.f.drain()[0], 1)
        for seq in range(2, 20):
            self.f.proof(1, seq=seq)
            self.assertEqual(self.f.drain()[0], 1)
        self.f.proof(1, seq=1)
        self.assertEqual(self.f.drain()[0], 1)

    def test_marker_before_checkpoint_interruption_is_conservative_at_every_cut(self):
        for cut in range(1, 15):
            f = Fixture()
            f.bind()
            for attempt in range(1, 16):
                f.proof(attempt)
            with self.assertRaises(RuntimeError):
                f.fold(crash_after_markers=cut)
            self.assertEqual(f.drain()[0], 15 - cut)
            for attempt in range(1, 16):
                f.proof(attempt)
            self.assertEqual(f.drain()[0], 15 - cut)
            f.proof(16)
            self.assertEqual(f.drain()[0], 16 - cut)
            f.db.close()

    def test_reopened_database_preserves_credit_and_replay_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "proof.sqlite")
            f = Fixture(path)
            f.bind()
            f.proof(1)
            self.assertEqual(f.drain()[0], 1)
            f.db.close()
            f = Fixture(path)
            f.proof(1)
            self.assertEqual(f.drain()[0], 1)
            f.proof(2)
            self.assertEqual(f.drain()[0], 2)
            f.db.close()

    def test_rewinding_cursor_cannot_reuse_consumed_comparisons(self):
        for attempt in range(1, 30):
            self.f.proof(attempt)
        self.assertEqual(self.f.drain()[0], 29)
        self.f.save(0, 0)
        self.assertEqual(self.f.drain()[0], 0)
        self.f.proof(30)
        self.assertEqual(self.f.drain()[0], 1)

    def test_idle_reads_do_not_rewrite_checkpoint(self):
        self.f.proof(1)
        self.f.drain()
        before = self.f.db.total_changes
        for _ in range(100):
            self.f.fold()
        self.assertEqual(self.f.db.total_changes, before)

    def test_corrupt_checkpoints_and_marker_conflicts_refuse(self):
        for passes, cursor in (("01", "10"), ("1", "0"), (str(FINAL + 1), "300000"), ("1", "-1"), ("1", str(2**63))):
            self.f.record(CONSTANTS["STATE"], CONSTANTS["CLASS"], 0, passes, cursor)
            with self.assertRaises(ValueError):
                self.f.fold()
        self.f.save(0, 0)
        self.f.proof(1)
        self.f.record(CONSTANTS["COUNTED"], f"a:{1:032x}", 0, "consumed", "wrong-class")
        with self.assertRaises(ValueError):
            self.f.fold()

    def test_seeded_evidence_oracle(self):
        for seed in range(50):
            rng = random.Random(seed)
            f = Fixture()
            f.bind()
            f.bind("b", "private-only")
            expected = set()
            for seq in range(1, 100):
                attempt = rng.randrange(1, 30)
                action = "a" if rng.randrange(4) else "b"
                found = f.db.execute("SELECT generation_hex FROM action_attempts WHERE id_hex=?", (f"{attempt:032x}",)).fetchone()
                owner = found[0] if found else action
                valid_receipt = bool(rng.randrange(3))
                passed = 1 if rng.randrange(4) else 0
                f.proof(attempt, seq=seq, action=action, receipt=valid_receipt, passed=passed)
                if action == owner == "a" and valid_receipt and passed:
                    expected.add(attempt)
            self.assertEqual(f.drain()[0], len(expected), seed)
            self.assertEqual(f.drain()[0], len(expected), seed)
            f.db.close()

    def test_final_stage_stops_positive_folding_without_zero_verification_floor(self):
        # Synthetic boundary injection verifies the terminal reducer branch,
        # not the existence of FINAL real comparisons.
        self.f.save(FINAL, FINAL)
        self.f.proof(1)
        before = self.f.db.total_changes
        self.assertEqual(self.f.fold(), (FINAL, FINAL))
        self.assertEqual(before, self.f.db.total_changes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
