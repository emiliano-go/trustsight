"""The public result dataclasses returned by :mod:`trustsight.api`."""

from __future__ import annotations
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..depth import DependencyReport

__all__ = ['AcknowledgedUrl', 'ClusterFinding', 'CycleReport', 'FailedPackage', 'FileChange', 'Finding', 'HistoryEntry', 'PivotMatch', 'PivotResult', 'Progress', 'ProgressHook', 'Report', 'ReviewResult', 'Status', 'SuppressedRule', 'TrackedPackage', '_evaluate_fact_dict_fallback']

@dataclass(frozen=True)
class Progress:
    """One progress tick from a long-running flow.

    ``current`` is -1 when the phase changed but there is nothing countable
    yet (the AUR metadata download reports no total until it starts).

    :ivar current: items completed so far, or -1 when the phase changed
        without a countable total.
    :ivar total: items expected, or 0 when the total is not yet known.
    :ivar phase: human-readable description of the current step.
    """

    current: int
    total: int
    phase: str

    @property
    def indeterminate(self) -> bool:
        """True when the total count is unknown or the current count is negative."""
        return self.current < 0 or not self.total

ProgressHook = Callable[[Progress], None]

@dataclass(frozen=True)
class Finding:
    """One rule that fired, with the evidence that made it fire.

    :ivar rule_id: rule identifier, such as ``R010``.
    :ivar severity: ``FATAL``, ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``
        or ``INFO``.
    :ivar weight: signed contribution this finding made to the score.
    :ivar description: plain-English explanation of what matched.
    :ivar file: file the match was found in, or "" when not file-specific.
    :ivar line: 1-based line number in that file, or ``None``.
    :ivar template: the rule template that produced the description.
    :ivar evidence: rule-specific match detail, as a plain dict.
    :ivar techniques: per-finding evasion-technique tags
        (``X002:spliced-variable`` and peers); additive instrumentation.

    Example:
        .. code-block:: python

            for finding in report.findings:
                print(finding.rule_id, finding.severity, finding.description)
    """

    rule_id: str
    severity: str
    weight: int
    description: str
    file: str = ""
    line: Optional[int] = None
    template: str = ""
    evidence: dict = field(default_factory=dict)
    #: Per-finding evasion-technique tags (``X002:spliced-variable`` and
    #: peers).  Additive instrumentation for the harness shape archive;
    #: never rendered, scored or suppressed.
    techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class SuppressedRule:
    """A rule that matched but was silenced by an override.

    It contributed nothing to the score.  It is reported anyway: a
    suppression a caller cannot see is a suppression it cannot audit.

    :ivar rule_id: rule identifier that was suppressed.
    :ivar severity: severity the rule would have contributed.
    :ivar override_reason: the reason recorded with the override.
    :ivar override_package: package the override is scoped to, or ``None``
        for an override that applies to every package.
    """

    rule_id: str
    severity: str = ""
    override_reason: str = ""
    override_package: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class AcknowledgedUrl:
    """A source URL explicitly acknowledged for this package.

    It did not contribute to SOURCE_BUCKET or NOVELTY.  It is reported
    anyway: an acknowledgement a caller cannot see is one it cannot audit,
    and the whole point of an ack (against a rule override) is that it
    covers one URL rather than the next one the package adds.

    :ivar url: the acknowledged URL.
    :ivar reason: the reason recorded with the acknowledgement.
    """

    url: str
    reason: str = ""

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class FileChange:
    """A single file that was added, removed, or modified in a diff.

    :ivar path: path of the file within the package tree.
    :ivar status: one of ``"added"``, ``"removed"`` or ``"modified"``.
    """

    path: str
    status: str
    """One of "added", "removed", "modified"."""

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class Report:
    """The analysis of one package: what ``trustsight inspect`` shows.

    :ivar package: package name.
    :ivar old_version: version the diff starts from.
    :ivar new_version: version the diff ends at.
    :ivar old_commit: commit the previous analysis recorded.
    :ivar new_commit: commit this analysis examined.
    :ivar score: heuristic score, 0 to 100.
    :ivar risk: the band the analysis supports.  Use this, never
        ``risk_level(score)``.
    :ivar risk_label: ``risk``, qualified in prose when coverage was
        incomplete.
    :ivar verdict: plain-English summary.  Always ends with a direction to
        review.
    :ivar findings: rules that fired, with the evidence that made them fire.
    :ivar suppressed: rules that matched but an override silenced.
    :ivar acknowledged_urls: source URLs acknowledged for this package;
        they did not score SOURCE_BUCKET or NOVELTY.
    :ivar changes: what the diff did, whether or not a rule matched.
        Context, not findings.
    :ivar coverage_gaps: non-empty means part of the change was not read.
        See :data:`COVERAGE_GAP_REASONS`.
    :ivar file_changes: each file the diff added, removed or modified.
    :ivar diff_shape_fp: the diff's deterministic shape fingerprint
        (instrumentation for corpus/harness clustering, never a score input).
    :ivar added_urls: URLs the change introduced.
    :ivar removed_urls: URLs the change removed.
    :ivar source_buckets: source categories the change touched, with counts.
    :ivar checksum_behavior: how the update affects package checksums.
    :ivar resolved_commands: shell commands the PKGBUILD resolves to.
    :ivar maintainer: current AUR maintainer, cleaned of control bytes.
    :ivar previous_maintainer: maintainer the previous analysis recorded.
    :ivar maintainer_changed: whether the maintainer changed in this update.
    :ivar dependency_changes: dependencies added or removed by this update.
    :ivar first_seen: no prior history, so novelty signals carry no weight
        yet.
    :ivar comparison_base: what this run compared against, one of
        ``"recorded"``, ``"parent"``, ``"none"``, or ``""``.
    :ivar is_trivial: the change was too small to warrant findings.
    :ivar diff_truncated: the diff was clamped before the rules read it.
    :ivar tree_analyzed: the AUR git tree was walked, not only the diff.
    :ivar version_comparison: how the installed version relates to the AUR
        pkgver, or "" if nothing compared them.
    :ivar adapter: which adapter produced this, ``git`` or ``corpus``.
    :ivar review_profile: review workload profile in force.
    :ivar review_threshold: score above which :attr:`flagged` is true.
    :ivar config_fingerprint: which rules, weights and overrides produced
        this.  Results are only comparable across runs with the same
        fingerprint.
    :ivar dependencies: analysed AUR dependencies, each with its own score
        and band.  Never folded into this package's :attr:`score`: depth is
        not part of the config fingerprint, so a score that moved with
        ``--depth`` would break comparability between runs.
    :ivar depth_truncated: the dependency walk stopped before the closure
        was exhausted.
    :ivar ioc_matches: signed-baseline indicator hits, reported outside the
        heuristic score.
    :ivar scan_truncated: the diff was clamped by line count before the
        rules read it.
    :ivar layers: the layer profile: per layer ``status`` and the rule ids
        that fired there.  A projection of :attr:`findings`.
    :ivar required_by: packages in the reviewed set that declare this one a
        dependency.  The reverse of :attr:`dependencies`, populated by
        ``review --deps``; empty on an ordinary review.
    :ivar coverage_gaps_carried: the subset of :attr:`coverage_gaps` whose
        root cause the previous recorded analysis already carried.  Still
        gaps; labelled "unchanged since the previous review" rather than
        read as introduced by this diff.
:ivar change: the typed change-as-data view,
        ``ChangeDelta.to_dict()``: file statuses, host and source deltas,
        checksum and dependency array deltas, and the resolved version
        move.  The prose summary renders the same object.
    :ivar unresolved_assignments: assignments the tokenizer refused on the
        analysed surface, each with its variable name, raw line and file.
        The value is "not seen" to every rule; this names the boundary.
    :ivar partial_files: install-script files whose diff showed only part
        of the file; their hook bodies were not read as whole scripts.
    :ivar resolution_coverage: how much of the diff the tokenizer could
        read, and which resolution-coupled R-rules matched.
    :ivar cached: this report serves the recorded analysis unchanged: the
        AUR HEAD, both versions, the dependency depth and the ruleset were
        all unchanged, so nothing was re-computed.
    :ivar cached_at: when the reused analysis was recorded; empty unless
        :attr:`cached`.
    :ivar layers: the assurance-layer profile: per layer,
        ``status`` (``fired``/``passed``/``unreadable``) and the rule ids
        that fired there.
    :ivar boundaries: the unified analysis boundaries (W1): one
        object per coverage gap and per W-series rendering.
    :ivar indicators: the indicator tier, promoted from
        ``ioc_matches``.  Outside the heuristic score.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            report = TrustSight().inspect("some-package")
            if report.flagged:
                print(report.verdict)
                for finding in report.findings:
                    print(finding.rule_id, finding.description)
    """

    package: str
    old_version: str = ""
    new_version: str = ""
    old_commit: str = ""
    new_commit: str = ""

    score: int = 0
    risk: str = ""
    """The band the analysis supports.  Use this, never ``risk_level(score)``."""
    risk_label: str = ""
    """``risk``, qualified in prose when coverage was incomplete."""
    verdict: str = ""
    """Plain-English summary.  Always ends with a direction to review."""

    findings: tuple[Finding, ...] = ()
    suppressed: tuple[SuppressedRule, ...] = ()
    acknowledged_urls: tuple[AcknowledgedUrl, ...] = ()
    """Source URLs acknowledged for this package; they did not score SOURCE_BUCKET or NOVELTY."""
    changes: tuple[str, ...] = ()
    """What the diff did, whether or not a rule matched.  Context, not findings."""

    coverage_gaps: tuple[str, ...] = ()
    """Non-empty means part of the change was not read.  See ``COVERAGE_GAP_REASONS``."""

    file_changes: tuple[FileChange, ...] = ()
    diff_shape_fp: str = ""
    """The diff's shape fingerprint: instrumentation, never score."""
    added_urls: tuple[str, ...] = ()
    removed_urls: tuple[str, ...] = ()
    source_buckets: dict = field(default_factory=dict)
    checksum_behavior: str = ""
    resolved_commands: tuple[str, ...] = ()

    maintainer: str = ""
    previous_maintainer: str = ""
    maintainer_changed: bool = False

    dependency_changes: dict = field(default_factory=dict)

    first_seen: bool = False
    """No prior history: novelty signals carry no weight yet."""
    comparison_base: str = ""
    """"recorded", "parent", "none", or "" when no comparison applied."""
    is_trivial: bool = False
    diff_truncated: bool = False
    tree_analyzed: bool = False
    version_comparison: str = ""
    """How the installed version relates to the AUR pkgver, or "" if nothing compared them."""
    adapter: str = "git"
    review_profile: str = "default"
    review_threshold: int = 20
    config_fingerprint: str = ""
    """Which rules, weights and overrides produced this.  Results are only
    comparable across runs with the same fingerprint."""

    dependencies: tuple["DependencyReport", ...] = ()
    """Analysed AUR dependencies, each with its own score and band.

    Never folded into this package's ``score``: depth is not part of the
    config fingerprint, so a score that moved with ``--depth`` would break
    B1 for anyone comparing two runs.
    """
    depth_truncated: bool = False
    """The dependency walk stopped before the closure was exhausted."""

    ioc_matches: tuple = ()
    """Signed-baseline indicator hits, reported outside the heuristic score.

    In the JSON body since IOC federation shipped, and reachable here only
    through ``to_dict()`` until now - which is the same asymmetry
    ``required_by`` had: a caller gating on indicator hits had to serialise
    the report to find them.
    """

    scan_truncated: bool = False
    """The diff was clamped by line count before the rules read it."""

    indicators: tuple = ()
    """The indicator tier: signed-baseline matches,
    promoted from ``ioc_matches`` to a first-class surface.  Outside the
    heuristic score, at maximum alert priority."""

    required_by: tuple = ()
    """Packages in the reviewed set that declare this one as a dependency.

    The reverse of :attr:`dependencies`, and populated by
    ``review --deps``, where the subject of the report is a dependency and
    the useful question is who needs it. Empty on an ordinary review, where
    the subject is the thing that was asked for.
    """

    coverage_gaps_carried: tuple[str, ...] = ()
    """The subset of :attr:`coverage_gaps` unchanged since the previous review."""

    change: dict = field(default_factory=dict)
    """The typed change-as-data view: ``ChangeDelta.to_dict``.

    The same object the prose summary renders, exposed for consumers that
    want the host/source/checksum/dependency deltas as data.
    """

    unresolved_assignments: tuple = ()
    """Assignments the tokenizer refused on the analysed surface.

    Each entry names the variable, quotes the raw line, and names its
    file.  The value is still "not seen" to every rule; this only names
    the boundary of the analysis.
    """

    partial_files: tuple = ()
    """Install-script files whose diff showed only part of the file.

    Their hook bodies are not read as whole scripts; the run carries a
    ``partial_file_analysis`` coverage gap instead.
    """

    resolution_coverage: dict = field(default_factory=dict)
    """How much of the diff the tokenizer could read.

    ``resolved_lines``, ``unresolved_lines``, the R-rules whose accuracy
    is coupled to resolution, and the subset that actually matched.
    """

    layers: dict = field(default_factory=dict)
    """The layer profile: per layer ``status`` and the rule
    ids that fired there.  A finding carries the layer where it caught, so
    this is a projection of :attr:`findings`.
    """

    boundaries: tuple = ()
    """The unified analysis boundaries (W1): one object per
    coverage gap and per W-series rendering, each naming whether it forbids
    a clean verdict.  Additive to :attr:`coverage_gaps` for one release.
    """

    cached: bool = False
    """The recorded analysis was served unchanged (#20); nothing was re-computed."""
    cached_at: str = ""
    """When the reused analysis was recorded; empty unless :attr:`cached`."""

    _raw: dict = field(default_factory=dict, repr=False, compare=False)
    _evaluated: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def contacts(self) -> dict:
        """The Contact Ledger panel: weight-0 first contacts, warm-only.

        A dict with ``available``, ``note`` and ``records``.  ``available``
        is False on a cold replay, where ``note`` carries the standing
        ``contact_ledger_unavailable`` text instead of a silent empty panel.
        """
        return dict(self._evaluated.get("contacts", {}) or {})

    @property
    def flagged(self) -> bool:
        """True when the score enters this report's configured review workload."""
        return self.score > self.review_threshold

    @property
    def flagged_dependencies(self) -> tuple["DependencyReport", ...]:
        """Analysed dependencies that cleared the threshold on their own."""
        return tuple(d for d in self.dependencies if d.flagged)

    @property
    def fully_vetted(self) -> bool:
        """False when the run could not read the whole change."""
        return not self.coverage_gaps

    @property
    def comparable_versions(self) -> bool:
        """False for a VCS package, whose AUR pkgver is a build-time placeholder."""
        from ..analysis.version import COMPARISON_INCONCLUSIVE

        return self.version_comparison != COMPARISON_INCONCLUSIVE

    @property
    def coverage_note(self) -> str:
        """The one-line caveat prefixed to the verdict, or "" when there is none."""
        from ..coverage import describe

        return describe(
            list(self.coverage_gaps),
            carried=self.coverage_gaps_carried,
            details={
                "unresolved_source": self.raw.get("unresolved_sources") or (),
                "partial_hunk": self.raw.get("partial_hunks") or (),
            },
        )

    @property
    def raw(self) -> dict:
        """The serialised ``PackageFact``, as stored in the database.

        This is the internal record, not the report: it uses the storage
        naming (``package_name``, ``final_score``) and always carries the
        score. Use :meth:`to_dict` for the body the CLI emits.
        """
        return dict(self._raw)

    def to_dict(self, *, include_score: bool = False, verbose: bool = False) -> dict:
        """The same JSON body ``trustsight review --json`` writes.

        Byte-for-byte the same key set as the CLI, and the same defaults:
        ``score``, ``risk`` and ``risk_label`` are withheld unless asked
        for, exactly as the CLI withholds them without ``--score`` or
        ``--risk``. ``include_score=True`` is this API's spelling of that
        flag, and ``verbose=True`` of ``--verbose``.

        Attribute access is a different act: ``report.score`` is always
        available, because reading a named field *is* the explicit request.
        What this method will not do is volunteer the number to a caller who
        only asked to serialise the result.

        :param include_score: include ``score``, ``risk`` and
            ``risk_label`` in the body.
        :param verbose: include ``score_breakdown`` and the verbose
            per-finding detail.
        :returns: the report as the CLI's JSON body.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                body = TrustSight().inspect("some-package").to_dict()
                scores_body = TrustSight().inspect(
                    "some-package").to_dict(include_score=True)
        """
        from ..reporting import report_body

        return report_body(
            self._evaluated or _evaluate_fact_dict_fallback(self),
            include_score=include_score,
            verbose=verbose,
        )

    def to_json(self, indent: int | None = 2, **kwargs: Any) -> str:
        """Serialize to a JSON string.

        Keyword arguments are passed to :meth:`to_dict`, so
        ``include_score`` and ``verbose`` behave exactly as they do there.

        :param indent: JSON indentation; ``None`` emits a compact document.
        :param kwargs: forwarded to :meth:`to_dict`.
        :returns: the report as JSON text.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                text = TrustSight().inspect("some-package").to_json(
                    include_score=True,
                )
        """
        return json.dumps(self.to_dict(**kwargs), indent=indent)

    def to_sarif(self, diff_text: str | None = None) -> dict:
        """This report as a SARIF 2.1.0 document.

        *diff_text*, when given, lets a removed-line finding anchor to the
        pre-image (``old_lineno``) instead of being dropped; without it,
        only findings whose line resolves in the post-state get a region.

        :param diff_text: the diff this report analysed, when held.
        :returns: a SARIF 2.1.0 document as a plain dict.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                sarif = TrustSight().inspect("some-package").to_sarif()
        """
        from ..reporting import report_to_sarif

        diffs = {self.package: diff_text} if diff_text else None
        return report_to_sarif([self.to_dict()], diffs)

@dataclass(frozen=True)
class FailedPackage:
    """A package whose analysis raised.  It was NOT vetted.

    :ivar package: package name.
    :ivar old_version: version the review started from.
    :ivar new_version: version the AUR advertised.
    :ivar error: the error message the analysis raised with.
    :ivar error_type: the exception class name.
    """

    package: str
    old_version: str = ""
    new_version: str = ""
    error: str = ""
    error_type: str = ""

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class ReviewResult:
    """The outcome of one ``review`` call.

    :ivar reports: one report per package that was vetted.
    :ivar failures: packages that could not be vetted.  A caller that
        iterates :attr:`reports` alone is looking at a partial review;
        :attr:`complete` says whether it was one.
    :ivar total_installed: installed packages considered, whether or not
        they needed a review.
    :ivar metadata_bootstrapped: this call did nothing but download the
        first AUR metadata snapshot.  There was no prior copy to diff
        against, so there is no delta yet; call ``review`` again.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            result = TrustSight().review(limit=10)
            for report in result.flagged:
                print(report.package, report.verdict)
            for failure in result.failures:
                print(failure.package, "NOT vetted:", failure.error)
    """

    reports: tuple[Report, ...] = ()
    failures: tuple[FailedPackage, ...] = ()
    total_installed: int = 0
    """Installed packages considered, whether or not they needed a review."""
    metadata_bootstrapped: bool = False
    """This call did nothing but download the first AUR metadata snapshot.
    There was no prior copy to diff against, so there is no delta yet; call
    ``review`` again."""

    @property
    def complete(self) -> bool:
        """False when at least one package could not be vetted."""
        return not self.failures

    @property
    def flagged(self) -> tuple[Report, ...]:
        """Reports that crossed the review threshold."""
        return tuple(r for r in self.reports if r.flagged)

    def __iter__(self) -> Iterator[Report]:
        return iter(self.reports)

    def __len__(self) -> int:
        return len(self.reports)

    def to_dict(
        self, *, include_score: bool = False, verbose: bool = False,
    ) -> list[dict]:
        """The JSON list ``trustsight review --json`` writes.

        ``include_score=True`` corresponds to ``--score`` or ``--risk``;
        ``verbose=True`` corresponds to ``--verbose``.

        :param include_score: include score and band fields in each body.
        :param verbose: include the verbose per-finding detail.
        :returns: one JSON body per report, failures included.
        """
        from ..reporting import report_body

        failures = [report_body({
            "package": failure.package,
            "old_version": failure.old_version,
            "new_version": failure.new_version,
            "verdict": (
                f"Analysis failed ({failure.error_type}): this package was NOT vetted."
            ),
            "failed": True,
        }, include_score=include_score, verbose=verbose) for failure in self.failures]
        return [
            report.to_dict(include_score=include_score, verbose=verbose)
            for report in self.reports
        ] + failures

@dataclass(frozen=True)
class HistoryEntry:
    """One scored revision in a package's analysis history.

    :ivar timestamp: when the analysis ran.
    :ivar old_version: version the analysis started from.
    :ivar new_version: version the analysis examined.
    :ivar score: score that run produced.
    :ivar risk: band that run produced.
    :ivar triggered_rules: rules that fired, when ``with_rules`` asked for
        them.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            for entry in TrustSight().history("some-package", limit=5):
                print(entry.timestamp, entry.score, entry.risk)
    """

    timestamp: str
    old_version: str
    new_version: str
    score: int
    risk: str
    triggered_rules: tuple[dict, ...] = ()

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class TrackedPackage:
    """A package tracked in the local database with its latest score.

    :ivar name: package name.
    :ivar version: version last recorded.
    :ivar last_checked: when the package was last analysed.
    :ivar score: score of the latest analysis, or ``None`` if never scored.
    :ivar risk: band of the latest analysis, or "" if never scored.
    :ivar maintainer: last recorded maintainer.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            for pkg in TrustSight().packages(limit=10):
                print(pkg.name, pkg.version, pkg.risk)
    """

    name: str
    version: str
    last_checked: str
    score: Optional[int]
    risk: str
    maintainer: str

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class Status:
    """The global status summary shown by ``trustsight status``.

    :ivar packages_tracked: packages in the database.
    :ivar total_analyses: analyses recorded.
    :ivar effective_observations: observations the novelty signals count.
    :ivar seed_observations: observations that came from the bundled seed.
    :ivar dependency_corpus_loaded: whether the dependency corpus is
        populated.
    :ivar config_dir: TrustSight configuration directory.
    :ivar database_path: path to the SQLite database file.
    :ivar config_fingerprint: identifies the rules, weights and overrides in
        force.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            state = TrustSight().status()
            print(state.packages_tracked, state.dependency_corpus_loaded)
    """

    packages_tracked: int
    total_analyses: int
    effective_observations: int
    seed_observations: int
    dependency_corpus_loaded: bool
    config_dir: Path
    database_path: Path
    config_fingerprint: str

    def to_dict(self) -> dict:
        """Serialize to a plain dict, converting Path fields to strings."""
        data = asdict(self)
        data["config_dir"] = str(self.config_dir)
        data["database_path"] = str(self.database_path)
        return data

@dataclass(frozen=True)
class ClusterFinding:
    """A corpus-wide pattern spanning several packages.

    :ivar rule_id: rule that matched across the cluster.
    :ivar name: human-readable name of the pattern.
    :ivar severity: severity the cluster is reported at.
    :ivar match: what the member packages have in common.
    :ivar members: packages that make up the cluster.
    """

    rule_id: str
    name: str
    severity: str
    match: str
    members: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class CycleReport:
    """One corpus cycle: what ``full-aur`` does once, or ``--watch`` repeats.

    :ivar added: packages new to the corpus this cycle.
    :ivar changed: packages whose corpus entry changed this cycle.
    :ivar removed: packages dropped from the corpus this cycle.
    :ivar processed: packages analysed this cycle.
    :ivar bootstrap: whether this cycle was part of an initial whole-AUR
        build.
    :ivar backfilling: whether this cycle was part of a ``--since`` replay.
    :ivar ioc_hits: ``(package, indicator)`` for packages whose analysis
        matched an IOC baseline entry this cycle.
    :ivar elapsed: wall-clock seconds the cycle took.
    :ivar flagged: ``(package, score)`` for everything this cycle scored 40
        or above, worst first.
    :ivar over_threshold: ``(package, score)`` for everything this cycle
        scored above the alerting bar (the benign corpus's p95 unless
        overridden), worst first.
    :ivar cluster_findings: corpus-wide patterns this cycle found.
    :ivar new_alerts: ``(package, rule_id)`` for clusters seen for the
        first time.  A cluster already reported on an earlier cycle is
        counted, not re-announced.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            for cycle in TrustSight().watch(cycles=2):
                print(cycle.processed, cycle.flagged)
    """

    added: int = 0
    changed: int = 0
    removed: int = 0
    processed: int = 0
    bootstrap: bool = False
    backfilling: bool = False
    elapsed: float = 0.0
    flagged: tuple[tuple[str, int], ...] = ()
    """``(package, score)`` for everything this cycle scored 40 or above, worst first."""
    over_threshold: tuple[tuple[str, int], ...] = ()
    """``(package, score)`` for everything this cycle scored above the
    alerting bar (the benign corpus's p95 unless overridden), worst first."""
    ioc_hits: tuple[tuple[str, str], ...] = ()
    """``(package, indicator)`` for packages whose analysis matched an IOC
    baseline entry this cycle."""
    cluster_findings: tuple[ClusterFinding, ...] = ()
    new_alerts: tuple[tuple[str, str], ...] = ()
    """``(package, rule_id)`` for clusters seen for the first time.  A cluster
    already reported on an earlier cycle is counted, not re-announced."""

    def to_dict(self) -> dict:
        """Serialize to a plain dict for ``full-aur`` JSON output."""
        return {
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "processed": self.processed,
            "bootstrap": self.bootstrap,
            "backfilling": self.backfilling,
            "elapsed": self.elapsed,
            "flagged": [list(f) for f in self.flagged],
            "over_threshold": [list(f) for f in self.over_threshold],
            "ioc_hits": [list(f) for f in self.ioc_hits],
            "cluster_findings": [c.to_dict() for c in self.cluster_findings],
            "new_alerts": [list(a) for a in self.new_alerts],
        }

@dataclass(frozen=True)
class PivotMatch:
    """A corpus package that references a pivot indicator.

    :ivar package: package that references the indicator.
    :ivar surface: where in the package the reference appears.
    :ivar detail: the matched reference itself.
    """

    package: str
    surface: str
    detail: str

    def to_dict(self) -> dict:
        """Serialize to a plain dict."""
        return asdict(self)

@dataclass(frozen=True)
class PivotResult:
    """Which corpus packages reference one indicator.

    The match is exact and reads only stored corpus material, never the
    network.  An empty ``matches`` means the corpus holds no reference, not
    that the indicator is harmless; if ``sources`` is empty there was no
    corpus to search at all.

    :ivar indicator: the indicator that was searched for.
    :ivar type: classified indicator type, such as ``package``, ``domain``
        or ``hash``.
    :ivar listed: whether the indicator appears in a signed baseline.
    :ivar confidence: confidence of the baseline listing, or "".
    :ivar matches: packages that reference the indicator.
    :ivar sources: corpora that were searched.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            result = TrustSight().pivot("evil.example")
            for match in result.matches:
                print(match.package, match.surface, match.detail)
    """

    indicator: str
    type: str
    listed: bool = False
    confidence: str = ""
    matches: tuple[PivotMatch, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def searched(self) -> bool:
        """True when a corpus was available to search."""
        return bool(self.sources)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for ``trustsight pivot --json``."""
        return {
            "indicator": self.indicator,
            "type": self.type,
            "listed": self.listed,
            "confidence": self.confidence,
            "matches": [m.to_dict() for m in self.matches],
            "sources": list(self.sources),
        }

def _uid_of(rule_id: str) -> Optional[str]:
    """The permanent uid behind *rule_id*, or ``None`` for a pseudo rule."""
    from ..registry import uid_of

    return uid_of(rule_id)


def _evaluate_fact_dict_fallback(report: "Report") -> dict:
    """An evaluated dict rebuilt from a Report's own fields.

    Only reached for a Report constructed directly rather than by one of the
    builders above, which is a thing callers and tests do. Rebuilt rather
    than refused so ``to_dict()`` never raises on a hand-made object.
    """
    return {
        "package": report.package,
        "old_version": report.old_version,
        "new_version": report.new_version,
        "old_commit": report.old_commit,
        "new_commit": report.new_commit,
        "version_comparison": report.version_comparison,
        "verdict": report.verdict,
        "score": report.score,
        "risk": report.risk,
        "risk_label": report.risk_label,
        "findings": [
            {
                "rule_id": f.rule_id, "severity": f.severity, "weight": f.weight,
                "file": f.file, "line": f.line, "description": f.description,
                "template": f.template, "evidence": dict(f.evidence),
                "rule_uid": _uid_of(f.rule_id),
            }
            for f in report.findings
        ],
        "suppressed_rules": [s.to_dict() for s in report.suppressed],
        "acknowledged_urls": [a.to_dict() for a in report.acknowledged_urls],
        "changes": list(report.changes),
        "coverage_gaps": list(report.coverage_gaps),
        "coverage_gaps_carried": list(report.coverage_gaps_carried),
        "change": dict(report._raw.get("change", {}) or {}),
        "unresolved_assignments": [
            dict(a) for a in report._raw.get("unresolved_assignments", ()) or ()
        ],
        "partial_files": list(report._raw.get("partial_files", ()) or ()),
        "resolution_coverage": dict(
            report._raw.get("resolution_coverage", {}) or {}),
        "file_changes": [c.to_dict() for c in report.file_changes],
        "ioc_matches": list(report._raw.get("ioc_matches", ())),
        "first_seen": report.first_seen,
        "comparison_base": report.comparison_base,
        "is_trivial": report.is_trivial,
        "diff_truncated": report.diff_truncated,
        "failed": False,
        "cached": report.cached,
        "cached_at": report.cached_at,
        "config_fingerprint": report.config_fingerprint,
        "review_profile": report.review_profile,
        "review_threshold": report.review_threshold,
        "flagged": report.flagged,
        # `flagged: false` is not "this package is fine" - it is "the score
        # this run produced did not reach the threshold", and when
        # `coverage_gaps` is non-empty that score was computed from an
        # incomplete read. The distinction is on `Report` as
        # `fully_vetted`, and it was the one field a machine consumer could
        # not see: a CI job parsing this dict got `score: 0`,
        # `findings: []`, `flagged: false` and no way to tell a clean
        # package from an unreadable one.
        "fully_vetted": report.fully_vetted,
        "raw": dict(report._raw),
    }
