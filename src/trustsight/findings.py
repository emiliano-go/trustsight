"""Finding construction helpers.

Every rule emits a finding, never a judgement:

    {
      "rule_id":  "H039",
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
    "H015": "critical build function modified: {touched}",
    "H016": "{position}() fetches {url} from outside the declared source array",
    "H017": "{position}() runs as root: {body}",
    "H018": "{position}() applies external patch from {patch_src}",
    "H019": "source URL downgraded from https to http: {url}",
    "H025": "{detail}",

    # --- Structural rules ---
    "H003": "http:// source added without checksum backing: {http_sources}",
    "C001": "checksum changed without corresponding source change",
    "C002": "checksum updated alongside version bump",
    "C003": "source URLs changed without version bump",
    "C004": "checksum array deleted while source URLs remain the same",
    "C005": "binary artifact from {bucket} source: {url}",
    "C006": "maintainer changed; new domains appeared: {new_domains}",
    "C007": "source array contains command substitution $( ) or backticks",

    # --- Checksum rules ---
    "H001": "checksum set to SKIP{skip_suffix}",
    "H002": "checksum array emptied",

    # --- Temporal rules ---
    "H020": "{detail}",
    "H021": "{detail}",
    "H022": "{detail}",

    # --- Context rules ---
    "H023": "PKGBUILD declares an install hook",
    "H024": "validpgpkeys removed after being populated",
    "H026": "maintainer changed: {previous_maintainer} → {current_maintainer} (new maintainer never seen in the AUR)",
    "H027": "findings span {n_categories} distinct capability categories",
    "H029": "package name '{pkg_name}' resembles the far more popular '{squatted}'",
    "H030": "diff adds {n_novel} novel or rare dependencies: {novel_names}",
    "H035": "{position}() invokes foreign package manager: {body}",
    "H036": "{position}() line carries {count} obfuscation indicators: {body}",
    "H065": "{detail}: {body}",

    # --- Phase 2: July delivery stack ---
    "H066": "ELF file committed to the repository: {path}",
    "H067": "{position}() probes its environment: {probe}",
    "H068": "{encoding} blob on the line decodes to {magic}",
    "H069": "{position}() generates {path} and then executes it",
    "H070": "{match}",
    "H072": "{position}() writes {path} and then executes it",

    # --- Phase 3: install-path persistence ---
    "H032": "{position}() writes into the user's home/rc: {path}",
    "H038": "{position}() stages work in a world-writable path: {path}",
    "H039": "systemd unit ExecStart points at runtime-writable path: {exec_target}",
    "H042": "{position}() drops a hidden file outside the build trees: {path}",
    "H062": "{position}() installs a pacman hook: {path}",

    # --- Phase 3: kill-chain composition ---
    "H040": "{position}() profiles the host: {probe}",
    "H043": "rule hits span {n_stages} distinct kill-chain stages: {stages}",

    # --- Phase 3: network surface ---
    "H004": "{position}() runs sudo: {body}",
    "H031": "{variable}={value!r} carries injection chars interpolated into a source URL: {url}",
    "H033": "{detail}",
    "H034": "source URL uses non-allowlisted scheme {scheme}: {url}",
    "H071": "{detail}",
    "H041": "{detail}: {body}",
    "H077": "{detail}: {body}",

    # --- Gap closures: parse-time fetch, signing keys, build flags ---
    "H078": "{detail}",
    "H079": "{detail}: {value}",
    "H080": "{detail}: {body}",
    "H081": "{position}() executes repo-committed file not declared in source=(): {path}",

    # --- Phase 4: Class B ---
    "H063": "epoch={epoch} newly introduced",
    "H064": "{field} claims '{dep_name}', {kind} but unrelated to '{package_name}'",

    # --- Phase 5: Class C longitudinal ---
    "H037": "{key} changed after {stable_for_n} stable observations",
    "H047": "configure_flags changed security flags after {stable_for_n} stable observations: {flags}",
    "H048": "removed dependency {vendored} now vendored in-tree after {stable_for_n} stable observations",
    "H049": "source {key} changed after {stable_for_n} stable observations",
    "H050": "version scheme changed {old_scheme} -> {new_scheme}",
    "H051": "pkgdesc changed after {stable_for_n} stable observations",
    "H054": "build {key} changed after {stable_for_n} stable observations: {old_value} -> {new_value}",
    "H045": "maintainer {maintainer} submitted {member_count} packages within the adoption window",
    "H052": "{member_count} unrelated packages share source repo {repo}",
    "H055": "{member_count} packages by maintainer {maintainer} modified in a short window",
    "H073": "introduction rate {introduced} deviates from baseline mean {mean} (z={z_score})",
    "H044": "ownership transition to {new}",
    "H074": "maintainer {maintainer} adopted and immediately modified {member_count} package(s)",
    "H086": "{package} was orphaned in the AUR and now has a maintainer",
    "H087": "the build recipe changed while source URLs, checksums and pkgver did not",
    "H088": "{package} was adopted from orphan, its recipe changed with no upstream move, and {position}() now resolves dependencies from a registry: {body}",
    "S001": "a function pipes itself into itself and backgrounds it: {body}",
    "S002": "recursive delete aimed outside the build tree: {body}",
    "S003": "writes to a raw block device: {body}",
    "S004": "unrecoverable delete of the operator's data: {body}",
    "S005": "loosens permissions outside the build tree: {body}",
    "S006": "stops, masks or kills a system service: {body}",
    "S007": "invokes or configures a coin miner: {body}",
    "S008": "erases the record of what ran: {body}",
    "X001": "an encoded payload is decoded straight into a shell: {body}",
    "X002": "the executable name is not a literal ({shape}): {body}",
    "X003": "the argument is obfuscated ({shape}): {body}",
    "X004": "the build hides its own output ({shape}): {body}",
    "X005": "reaches a home directory by an alternative spelling ({shape}): {body}",
    "X006": "a source points somewhere unexpected ({shape}): {body}",
    "X007": "{count} evasion techniques in one diff: {techniques}",
    "H046": "depends on {dep}, which was orphaned/adopted this cycle",
    "H053": "{prefix} ecosystem sourced from {hosts}",
    "H057": "transitive dependency reaches adopted-from-orphan {dep}",
    "H058": "maintainer {maintainer} activity {activity} vs baseline mean {mean} (z={z_score})",
    "H059": "name/repo divergence",
    "H060": "transitive dependency reaches orphaned {dep}",
    "H061": "dependency hub ({dependents} dependents)",

    "H076": "{position}() writes to {path}, outside $pkgdir/$srcdir",

    # --- Class E indicator ---
    "H056": "{surface} matches known indicator {ioc_value} ({confidence}, {provenance})",
    # --- Build environment overrides ---
    "R078": "compression command override: {body}",
    "R091": "privilege escalation override: {body}",
    "R099": "trap statement: {body}",
    "R104": "error handling suppressed: {body}",
    "H096": "DLAGENTS is assigned, redirecting source downloads: {body}",
    "H097": "function '{func_name}' is redefined: {body}",
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


# B8.  Rules whose evidence is not a line of the recipe: maintainer state,
# timing, corpus-wide clustering, dependency-graph shape.  These declare an
# evidence class instead of a location, because a missing location must not
# be indistinguishable from a rule that forgot to set one.
NON_CONTENT_RULES = {
    "H020": "temporal", "H021": "temporal", "H022": "temporal",
    "H026": "maintainer", "H027": "maintainer", "H028": "maintainer",
    "H029": "naming", "H030": "naming", "H037": "longitudinal",
    "H044": "corpus", "H045": "corpus", "H046": "corpus", "H047": "longitudinal",
    "H048": "longitudinal", "H049": "longitudinal", "H050": "longitudinal",
    "H051": "longitudinal", "H052": "corpus", "H053": "corpus",
    "H054": "longitudinal", "H055": "corpus", "H057": "corpus",
    "H058": "corpus", "H059": "corpus", "H060": "corpus", "H061": "corpus",
    "H073": "corpus", "H074": "corpus",
    "D001": "dependency", "D002": "dependency", "D003": "dependency",
    "D004": "dependency",
    "R059": "context", "H015": "context", "H023": "context", "H025": "context",
    "H031": "context", "H038": "context", "H043": "composite",
    "H065": "reconstruction", "H079": "context",
}
