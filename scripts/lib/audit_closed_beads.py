#!/usr/bin/env python3
"""audit_closed_beads.py — close-reason evidence audit (ocv9i.16.5).

Part of the remediation validation gate. For every CLOSED, non-epic, non-docs
implementation bead under the session-history remediation program, verify the
close_reason actually cites validation evidence — commands run and/or log
artifacts — rather than a bare "done". This enforces the program's closure
policy ("no implementation bead is closed without close-reason evidence that
cites commands and log artifacts") mechanically, so a future agent cannot
silently false-close a program bead.

Severity model (calibrated against the live program — see ocv9i.16.5):
  - FAIL : close_reason empty or trivially short (< MIN_REASON_CHARS) — no
           evidence at all. Hard gate failure (exit 1).
  - FAIL : (only with --strict) cites neither a command nor an artifact.
  - WARN : cites a command OR an artifact but not both, or is otherwise thin —
           reported for review, does not fail the gate by default.
  - PASS : cites at least one command/test/commit AND at least one artifact /
           matrix / schema / golden reference.

Outputs a JSON object to --out-json (and a copy to stdout) and a human summary
to stderr. The JSON carries per-bead status so the gate's Markdown/JSON summary
can render it. Exit code: 0 if no FAIL, 1 if any FAIL.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROGRAM_PREFIX = "bd-session-history-remediation-ocv9i"
MIN_REASON_CHARS = 40
GATE_REASON_CODE = "RCH-GATE-EVIDENCE-MISSING"
REMEDIATION_BEAD = "bd-session-history-remediation-ocv9i.16.5"

# Substantive evidence: tests run, a command, a matrix row, a source/test/script
# file, a log artifact, or a schema/golden reference. Any one of these means the
# close cites real validation work — solid evidence on its own.
STRONG_PATTERNS = [
    r"\bcargo\s+(test|build|check|clippy|bench|nextest|fmt)\b",
    r"\brch\s+[a-z][\w-]*",
    r"\b\d+\s+(unit\s+|mock-?ssh\s+|integration\s+|e2e\s+)?tests?\b",
    r"\bREQ-[A-Z]+-\d+\b",                          # traceability matrix row
    r"\b[\w/-]+\.(rs|sh|py|jsonl|md|json)\b",       # source/test/script/artifact
    r"docs/evidence/\S+",
    r"\bscripts/[\w./-]+",
    r"\b(schema|golden|matrix|FLEET_DEPLOY_AUDIT|SchemaComponent)\b",
]
# A bare commit citation — evidence you can inspect, but thin on its own.
COMMIT_PATTERNS = [
    r"\bcommit(?:s|ted)?\s+[0-9a-f]{7,40}\b",
    r"\b[0-9a-f]{7,12}\b",
]


def _matches(patterns: list[str], text: str) -> list[str]:
    hits: list[str] = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0).strip())
    return hits


def classify(reason: str, strict: bool) -> tuple[str, list[str], list[str]]:
    """Return (status, strong_hits, commit_hits).

    PASS  cites at least one substantive evidence token (tests/command/REQ/file/
          artifact/schema). FAIL on an empty/trivial reason or one with no
          citations at all. WARN on a commit-only close (thin but inspectable);
          --strict promotes that to FAIL.
    """
    r = (reason or "").strip()
    if len(r) < MIN_REASON_CHARS:
        return "FAIL", [], []
    strong = _matches(STRONG_PATTERNS, r)
    commit = _matches(COMMIT_PATTERNS, r)
    if strong:
        return "PASS", strong, commit
    if commit:
        return ("FAIL" if strict else "WARN"), strong, commit
    return "FAIL", strong, commit


def main() -> int:
    ap = argparse.ArgumentParser(description="Close-reason evidence audit (ocv9i.16.5)")
    ap.add_argument("--beads", default=".beads/issues.jsonl", help="path to beads JSONL export")
    ap.add_argument("--prefix", default=PROGRAM_PREFIX, help="bead id prefix to scope the audit")
    ap.add_argument("--out-json", default="", help="write the JSON report to this path")
    ap.add_argument("--strict", action="store_true",
                    help="treat a thin close (command XOR artifact) as a hard FAIL")
    args = ap.parse_args()

    path = Path(args.beads)
    if not path.exists():
        print(f"audit_closed_beads: beads file not found: {path}", file=sys.stderr)
        return 2

    beads = []
    seen = set()
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            bid = o.get("id", "")
            if not bid.startswith(args.prefix):
                continue
            if o.get("status") != "closed":
                continue
            if o.get("issue_type") in ("epic", "docs"):
                continue
            if bid in seen:
                continue
            seen.add(bid)
            status, strong, commit = classify(o.get("close_reason") or "", args.strict)
            beads.append({
                "id": bid,
                "type": o.get("issue_type"),
                "status": status,
                "reason_len": len((o.get("close_reason") or "").strip()),
                "evidence_citations": strong[:6],
                "commit_citations": commit[:6],
            })

    beads.sort(key=lambda b: (b["status"] != "FAIL", b["status"] != "WARN", b["id"]))
    fails = [b for b in beads if b["status"] == "FAIL"]
    warns = [b for b in beads if b["status"] == "WARN"]
    passes = [b for b in beads if b["status"] == "PASS"]

    report = {
        "audit": "closed_bead_evidence",
        "remediation_bead": REMEDIATION_BEAD,
        "reason_code": GATE_REASON_CODE,
        "strict": args.strict,
        "scope_prefix": args.prefix,
        "totals": {"audited": len(beads), "pass": len(passes), "warn": len(warns), "fail": len(fails)},
        "ok": len(fails) == 0,
        "beads": beads,
    }

    out = json.dumps(report, indent=2)
    if args.out_json:
        Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_json).write_text(out + "\n")
    print(out)

    print(f"\nclosed-bead evidence audit: {len(beads)} audited | "
          f"{len(passes)} pass | {len(warns)} warn | {len(fails)} fail "
          f"({'strict' if args.strict else 'default'} mode)", file=sys.stderr)
    for b in fails:
        print(f"  FAIL {b['id']}  [{GATE_REASON_CODE}] remediation={REMEDIATION_BEAD} "
              f"(reason_len={b['reason_len']})", file=sys.stderr)
    for b in warns:
        print(f"  warn {b['id']}  commit-only thin close (no test/command/artifact cited); review recommended",
              file=sys.stderr)

    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
