"""Finding construction helpers.

Every rule emits a finding, never a judgement:

    {
      "rule_id":  "R085",
      "file":     "PKGBUILD" | "<name>.install" | ".SRCINFO" | "<path>",
      "line":     13,                    # null when no line exists
      "template": "post_install writes to /etc/systemd/system/",
      "evidence": {...},                 # the declared facts that triggered it
      "severity": "HIGH",
    }

``stamp()`` attaches the ``template`` and ``evidence`` keys that this
contract requires.  ``TEMPLATES`` is the render vocabulary; verdict.py
formats a finding's template with its evidence.
"""

TEMPLATES: dict[str, str] = {
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
    "R006": "http:// source added without checksum backing: {http_sources}",
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
    "R081": "{position}() invokes foreign package manager: {body}",
    "R082": "{position}() line carries {count} obfuscation indicators: {body}",
}


def stamp(finding: dict, template: str | None = None) -> dict:
    """Attach ``template`` and ``evidence`` keys to *finding*.

    *template* wins when given; otherwise the registry is consulted for
    the rule_id, and finally a ``"{name}: {match}"`` fallback keeps config
    rules readable.  ``evidence`` is the declared facts: the ``params``
    dict when present, plus the raw matched text as ``match``.  Findings
    without a line get an explicit ``"line": null`` rather than an omitted
    key, per the output contract.
    """
    if template is None:
        template = TEMPLATES.get(finding.get("rule_id", ""))
    if template is None:
        name = finding.get("name", finding.get("rule_id", ""))
        template = f"{name}: {{match}}"
    finding["template"] = template

    evidence = dict(finding.get("params") or {})
    match = finding.get("match")
    if match and "match" not in evidence:
        evidence["match"] = match
    finding["evidence"] = evidence

    finding.setdefault("line", None)
    finding.setdefault("file", "")
    return finding
