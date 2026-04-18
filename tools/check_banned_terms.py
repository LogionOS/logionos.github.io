#!/usr/bin/env python3
"""
Banned-terms CI check.

Enforces the locked Creator Risk Layer product-boundary (see
docs/creator-risk-layer-design-decisions.md and the v3 spec, section 0).
Any copy that drifts past the boundaries below must fail CI before it can
reach a customer-facing surface.

Why this exists

The three customer-facing surfaces (`/v1/creator-check` responses, the
Chrome extension UI, the marketing website) must NOT claim to provide:

  - legal advice
  - copyright clearance
  - compliance guarantees
  - guarantee-against-infringement
  - a shield / safe harbor against claims

"Copy drift past these lines is a P0 bug" per spec sec 0.

Usage

    python tools/check_banned_terms.py [--root PATH] [--verbose]

Exits 1 with a file+line report if any banned term appears in a non-allowlisted
file. Exits 0 otherwise.

Scope

- The default scan is `HTML / MD / TS / TSX / JS / PY` files under the repo
  root, minus `ALLOWLIST_PATTERNS` (tests, vendor dirs, this file itself,
  the spec docs that legitimately quote the banned terms in order to forbid
  them, and regulation packs).
- Matches are case-insensitive whole-word-boundary regex matches. Rule of
  thumb: write code/copy that says "we surface disclosure suggestions, not
  legal advice" without using the banned phrasings themselves.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


BANNED_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("legal_advice", re.compile(r"\blegal\s+advice\b", re.I),
     "Never claim to provide legal advice."),
    ("copyright_clearance", re.compile(r"\bcopyright\s+clearance\b", re.I),
     "Never claim to provide copyright clearance."),
    ("compliance_guarantee", re.compile(r"\bcompliance\s+guarantee[ds]?\b", re.I),
     "Never claim compliance is guaranteed."),
    ("guaranteed_compliance", re.compile(r"\bguarantee[ds]?\s+compliance\b", re.I),
     "Never claim to guarantee compliance."),
    ("guaranteed_not_to_infringe", re.compile(
        r"\bguarantee[ds]?\s+(?:not|no)\s+(?:to\s+)?infring", re.I),
     "Never claim a guarantee against infringement."),
    ("attorney_client", re.compile(r"\battorney[-\s]client\b", re.I),
     "Do not imply any attorney-client relationship."),
    ("will_clear_rights", re.compile(
        r"\b(?:will|we)\s+clear\s+(?:your\s+)?rights?\b", re.I),
     "Do not claim to clear rights."),
    ("creator_shield", re.compile(
        r"\bcreator\s+shield\b(?!.*(?:is\s+(?:a\s+)?banned|explicitly\s+banned|is\s+not))",
        re.I),
     "'Creator Shield' is explicitly banned as an external brand."),
]

NEGATION_WINDOW = 80
NEGATORS = re.compile(
    r"\b(?:not|no|never|without|avoid|do\s+not|does\s+not|doesn[' ]t|"
    r"don[' ]t|cannot|can[' ]t|NOT)\b",
    re.I,
)
BOUNDARY_DESCRIPTORS = re.compile(
    r"\b(?:banned|forbidden|prohibited|disallowed|allowlist|banned_term|"
    r"banned_id|BANNED_PATTERNS|disclaimer|boundary|explicitly\s+banned|"
    r"product\s+boundary)\b",
    re.I,
)


def is_negated(line: str, match: re.Match[str]) -> bool:
    """True if the banned phrase is negated or quoted as a boundary example.

    Handles common negation patterns in disclaimers:
      - "does NOT provide legal advice"
      - "not a copyright clearance"
      - "never a compliance guarantee"
      - "not legal advice"
      - "NOT a copyright clearance"
    And recognises docstrings / comments that are merely listing the banned
    term itself (e.g., in this script's own BANNED_PATTERNS table).
    """
    pre_start = max(0, match.start() - NEGATION_WINDOW)
    pre_window = line[pre_start:match.start()]
    if NEGATORS.search(pre_window):
        return True
    post_end = min(len(line), match.end() + NEGATION_WINDOW)
    post_window = line[match.end():post_end]
    if NEGATORS.search(post_window):
        return True
    if BOUNDARY_DESCRIPTORS.search(line):
        return True
    return False

ALLOWLIST_PATTERNS = [
    "tools/check_banned_terms.py",
    "tools/check-banned-terms.js",
    ".github/workflows/banned-terms.yml",
    "docs/creator-risk-layer-spec.md",
    "docs/creator-risk-layer-design-decisions.md",
    "regulations/",
    "tests/",
    "scripts/",
    "node_modules/",
    "venv/",
    ".venv/",
    "dist/",
    "build/",
    ".next/",
    ".git/",
]

DEFAULT_EXTENSIONS = {".html", ".md", ".ts", ".tsx", ".js", ".jsx", ".py"}


def is_allowlisted(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    return any(rel == p or rel.startswith(p) for p in ALLOWLIST_PATTERNS)


_CONTEXT_LINES = 3


def scan_file(path: Path) -> list[tuple[int, str, str, str]]:
    """Return list of (lineno, banned_id, message, line_excerpt) hits.

    Scanning is line-oriented, but negation / boundary-descriptor detection
    considers the previous _CONTEXT_LINES to handle disclaimers that wrap
    across multiple source lines. E.g., the line with 'copyright clearance'
    is treated as negated if any of the previous 3 lines contains 'not' or
    'product boundary'.
    """
    hits: list[tuple[int, str, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return hits
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        context_start = max(0, i - 1 - _CONTEXT_LINES)
        context_end = min(len(lines), i + _CONTEXT_LINES)
        context = " ".join(lines[context_start:context_end])
        for banned_id, pat, msg in BANNED_PATTERNS:
            for m in pat.finditer(line):
                ctx_m = re.search(pat, context) or m
                if is_negated(context, ctx_m):
                    continue
                hits.append((i, banned_id, msg, line.strip()[:200]))
                break
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root: Path = args.root.resolve()
    all_hits: list[tuple[Path, int, str, str, str]] = []
    scanned = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in DEFAULT_EXTENSIONS:
            continue
        if is_allowlisted(path, root):
            continue
        scanned += 1
        for lineno, bid, msg, excerpt in scan_file(path):
            all_hits.append((path, lineno, bid, msg, excerpt))

    if args.verbose:
        print(f"scanned {scanned} files under {root}", file=sys.stderr)

    if not all_hits:
        print(f"banned-terms check OK ({scanned} files scanned)")
        return 0

    print("banned-terms check FAILED:", file=sys.stderr)
    for path, lineno, bid, msg, excerpt in all_hits:
        rel = path.relative_to(root).as_posix()
        print(f"  {rel}:{lineno}  [{bid}] {msg}", file=sys.stderr)
        print(f"      > {excerpt}", file=sys.stderr)
    print(
        f"\n{len(all_hits)} banned-term hit(s) in {len({h[0] for h in all_hits})} "
        "file(s). See tools/check_banned_terms.py for the full banned list.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
