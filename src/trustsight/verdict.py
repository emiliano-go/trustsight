from .schema import PackageFact, ScoreEntry

_SEVERITY_ORDER = ["FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_TEMPLATES: dict[str, str] = {
    # --- Dependency rules ---
    "D001": "novel dependency '{dep_name}' added in {field}",
    "D002": "typosquatted dependency: {field} '{dep_name}' impersonates '{impersonated}'",
    "D003": "build target can reach the network via {new_network}",
    "D004": "{field} '{dep_name}' declares an established unrelated package",

    # --- Build / install rules ---
    "R060": "critical build function modified: {touched}",
    "R061": "{position}() fetches {url} from outside the declared source array",
    "R062": "{position}() runs as root: {body}",
    "R063": "{position}() applies external patch from {patch_src}",
    "R064": "source URL downgraded from https to http: {url}",
    "R070": "{detail}",

    # --- Structural rules ---
    "C001": "checksum changed without corresponding source change",
    "C002": "checksum updated alongside version bump",
    "C003": "source URLs changed without version bump",
    "C004": "checksum array deleted while source URLs remain the same",
    "C005": "binary artifact from {bucket} source: {url}",
    "C006": "maintainer changed; new domains appeared: {new_domains}",
    "C007": "source array contains command substitution $( ) or backticks",

    # --- Checksum rules ---
    "R004": "checksum set to SKIP{skip_suffix}",
    "R005": "checksum array emptied",

    # --- Temporal rules ---
    "R065": "{detail}",
    "R066": "{detail}",
    "R067": "{detail}",

    # --- Context rules ---
    "R068": "PKGBUILD declares an install hook",
    "R069": "validpgpkeys removed after being populated",
    "R071": "maintainer changed: {previous_maintainer} → {current_maintainer} (new maintainer never seen in the AUR)",
    "R072": "findings span {n_categories} distinct capability categories",
    "R074": "package name '{pkg_name}' resembles the far more popular '{squatted}'",
    "R075": "diff adds {n_novel} novel or rare dependencies: {novel_names}",
}


def _render(entry: ScoreEntry, fact: PackageFact) -> str:
    template = _TEMPLATES.get(entry.rule_id)
    if template is None:
        return f"{entry.reason} [{entry.rule_id}]"
    params = dict(entry.params) if entry.params else {}
    if fact:
        for field in ("package_name", "previous_maintainer", "current_maintainer"):
            val = getattr(fact, field, None)
            if val and field not in params:
                params[field] = val
    try:
        return f"{template.format(**params)} [{entry.rule_id}]"
    except (KeyError, ValueError):
        return f"{entry.reason} [{entry.rule_id}]"


def fallback_verdict(fact: PackageFact) -> str:
    if fact.first_seen:
        seen = "No prior history for this package"
        if not fact.old_version and not fact.new_version:
            return f"{seen}. Insufficient data for a verdict."
        return f"First analysis. {seen}. No version bump confirmed yet."

    reasons = []
    if fact.diff_summary.files_changed:
        reasons.append(f"modified {', '.join(fact.diff_summary.files_changed)}")
    if fact.source_changes.added_urls:
        reasons.append(f"added {len(fact.source_changes.added_urls)} source URL(s)")
    if fact.maintainer_changed:
        reasons.append("maintainer changed")
    if not reasons:
        reasons.append("no structural changes")
    change_summary = "; ".join(reasons)

    fired = [e for e in fact.score_breakdown if e.weight > 0 or e.severity == "FATAL"]
    if not fired:
        return f"Version bump. {change_summary}. No risk signals fired."

    fired.sort(key=lambda e: (
        _SEVERITY_ORDER.index(e.severity) if e.severity in _SEVERITY_ORDER else 99,
        -e.weight,
    ))
    worst = fired[0]
    if worst.severity == "FATAL":
        detail = _render(worst, fact)
        return (
            f"{change_summary}. {detail}. "
            f"The package is attempting to deceive the reviewer, so the score "
            f"is capped at maximum regardless of other evidence."
        )

    details = [_render(e, fact) for e in fired[:5]]
    if len(fired) > 5:
        details.append(f"and {len(fired) - 5} more signal(s)")
    signals = "; ".join(details)
    return f"Version bump. {change_summary}. Signals: {signals}."
