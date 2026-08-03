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

    # --- Phase 2: July delivery stack ---
    "R118": "ELF file committed to the repository: {path}",
    "R119": "{position}() probes its environment: {probe}",
    "R120": "{encoding} blob on the line decodes to {magic}",
    "R121": "{position}() generates {path} and then executes it",
    "R122": "{match}",
    "R124": "{position}() writes {path} and then executes it",

    # --- Phase 3: install-path persistence ---
    "R077": "{position}() writes into the user's home/rc: {path}",
    "R084": "{position}() stages work in a world-writable path: {path}",
    "R085": "systemd unit ExecStart points at runtime-writable path: {exec_target}",
    "R088": "{position}() drops a hidden file outside the build trees: {path}",
    "R114": "{position}() installs a pacman hook: {path}",

    # --- Phase 3: kill-chain composition ---
    "R086": "{position}() profiles the host: {probe}",
    "R089": "rule hits span {n_stages} distinct kill-chain stages: {stages}",

    # --- Phase 3: network surface ---
    "R009": "{position}() runs sudo: {body}",
    "R076": "{variable}={value!r} carries injection chars interpolated into a source URL: {url}",
    "R080": "source URL uses non-allowlisted scheme {scheme}: {url}",
    "R123": "{detail}",

    # --- Phase 4: Class B ---
    "R115": "epoch={epoch} newly introduced",
    "R116": "{field} claims '{dep_name}', {kind} but unrelated to '{package_name}'",
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
