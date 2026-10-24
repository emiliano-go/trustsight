"""The :class:`TrustSight` client: the public methods for analysis, review, corpus cycles and stored state."""

from __future__ import annotations
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Sequence
from ._models import CycleReport, FailedPackage, HistoryEntry, PivotMatch, PivotResult, ProgressHook, Report, ReviewResult, Status, TrackedPackage
from ._reports import _cycle_report, _hook, _report_from_fact, _report_from_result
from ._validation import MAX_API_HISTORY, MAX_API_NAME_BYTES, MAX_API_PACKAGES, MAX_API_REPOS, PackageNotFound, TrustSightError, _validate_limit, _validate_name, _validate_names, _validate_nonnegative, _validate_text

__all__ = ['TrustSight']

class TrustSight:
    """A configured TrustSight instance.

    Construction does no I/O.  The config directory, the database and the
    bundled seed are prepared on the first call that needs them, so a
    process that builds one of these and never uses it pays nothing.

    :param auto_import_seed: whether to import the bundled observation seed
        on first use.  ``None`` (the default) follows ``seed.auto_import``
        in the config file, which is what the CLI does.  Set ``False`` to
        run against a cold database on purpose; note that a cold database
        makes every novelty signal meaningless, and TrustSight reports the
        band as ``Inconclusive`` rather than pretending otherwise.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            with TrustSight() as ts:
                report = ts.inspect("some-package")
                print(report.package, report.risk, report.verdict)
    """

    def __init__(self, *, auto_import_seed: Optional[bool] = None):
        self._auto_import_seed = auto_import_seed
        self._ready = False

    # --- lifecycle ---------------------------------------------------

    def _ensure_ready(self, quiet: bool = True) -> None:
        if self._ready:
            return
        from ..config import ensure_default_configs, load_config
        from ..db import init_db, maybe_auto_import_seed

        ensure_default_configs()
        init_db()
        wanted = self._auto_import_seed
        if wanted is None:
            wanted = load_config().get("seed", {}).get("auto_import", True)
        if wanted:
            maybe_auto_import_seed(quiet=quiet)
        self._ready = True

    def close(self) -> None:
        """Release the database connections held by this thread.

        Not required for a short-lived process; useful in a long-running
        one, or in tests that swap the database out underneath.  Using the
        instance as a context manager calls this on exit.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                ts = TrustSight()
                try:
                    report = ts.inspect("some-package")
                finally:
                    ts.close()
        """
        from ..db import close_connections

        close_connections()

    def __enter__(self) -> "TrustSight":
        self._ensure_ready()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- introspection -----------------------------------------------

    @property
    def config_dir(self) -> Path:
        """The TrustSight configuration directory (``~/.config/trustsight/``).

        :returns: the configuration directory path.
        """
        from ..config import CONFIG_DIR

        return CONFIG_DIR

    @property
    def database_path(self) -> Path:
        """The path to the SQLite database file.

        :returns: the database file path.
        """
        from ..db import get_db_path

        return get_db_path()

    @property
    def config_fingerprint(self) -> str:
        """Identifies the rules, weights and overrides in force.

        Two reports are only comparable when their fingerprints match.

        :returns: a stable digest of the effective configuration.
        """
        from ..config import config_fingerprint

        self._ensure_ready()
        return config_fingerprint()

    def config(self) -> dict:
        """The effective configuration, defaults merged with the user's file.

        :returns: the merged config as a plain dict.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                thresholds = TrustSight().config().get("thresholds", {})
        """
        from ..config import load_config

        self._ensure_ready()
        return load_config()

    def status(self) -> Status:
        """Database and corpus health: what ``trustsight status`` reports.

        :returns: the current :class:`Status`.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                state = TrustSight().status()
                print(state.packages_tracked, state.dependency_corpus_loaded)
        """
        from ..config import config_fingerprint
        from ..db import (
            count_observations,
            dependency_table_populated,
            effective_observation_count,
            get_all_packages,
            seed_observation_count,
        )

        self._ensure_ready()
        return Status(
            packages_tracked=len(get_all_packages()),
            total_analyses=count_observations(),
            effective_observations=effective_observation_count(),
            seed_observations=seed_observation_count(),
            dependency_corpus_loaded=dependency_table_populated(),
            config_dir=self.config_dir,
            database_path=self.database_path,
            config_fingerprint=config_fingerprint(),
        )

    # --- analysis ----------------------------------------------------

    def inspect(self, package: str, *, check_aur: bool = True,
                depth: Optional[int] = None, record: bool = False) -> Report:
        """Analyse one package: what ``trustsight inspect`` shows.

        Fetches the package's AUR git repository, diffs it against the last
        state this database saw, and runs every rule.  Read-only by default:
        nothing is written, so the same call against the same state returns
        the same report.  Pass ``record=True`` to persist the run as an
        observation and analysis history, which is what makes the *next*
        call's novelty signals mean anything.

        :param check_aur: verify the package exists before analysing.  Set
            ``False`` to skip the RPC round trip when you already know it
            does; analysis of a name that does not exist then returns a
            first-seen report with nothing in it rather than raising.
        :param depth: AUR dependency levels to analyse: ``0`` off, ``1``
            (the default) direct dependencies, ``n`` levels, ``-1`` every
            level, bounded by ``depth.MAX_DEPTH_LEVELS`` and
            ``depth.MAX_DEPTH_NODES``.  ``None`` uses ``[depth] levels`` from
            the config.  Each dependency is a full analysis with its own
            score on ``Report.dependencies``; none of it moves this
            report's ``score``.
        :returns: the analysis of *package*.
        :raises PackageNotFound: the name is in neither the AUR nor the
            local database.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                report = TrustSight().inspect("some-package")
                if report.flagged:
                    print(report.verdict)
                    for finding in report.findings:
                        print(finding.rule_id, finding.description)
        """
        from ..analysis import analyze_package

        _validate_name(package)
        self._ensure_ready()

        if check_aur:
            from ..db import get_package
            from ..discovery import get_aur_package_info

            if package not in get_aur_package_info([package]) and get_package(package) is None:
                raise PackageNotFound(package)

        return _report_from_fact(
            analyze_package(package, depth=depth, record=record)
        )

    def analyze_text(
        self,
        package: str,
        new_pkgbuild: str,
        old_pkgbuild: Optional[str] = None,
        *,
        maintainer: str = "",
        srcinfo: Optional[str] = None,
        last_modified: Optional[int] = None,
        first_submitted: Optional[int] = None,
        previous_modified: Optional[int] = None,
        record: bool = False,
    ) -> Report:
        """Analyse PKGBUILD text directly, with no git and no network.

        For vetting a PKGBUILD you already hold: a pull request, a
        generated file, a CI checkout.  Nothing is fetched and nothing is
        recorded as an observation, so the novelty signals see only what
        the database already knew.

        The timestamps are optional and are Unix seconds.  Without them the
        age-based rules have no clock and stay silent, which is why
        ``Report.adapter`` reads ``corpus`` here: this is a narrower look at
        the package than :meth:`inspect` gets.

        :param package: package name the analysis is attributed to.
        :param new_pkgbuild: the complete post-change ``PKGBUILD`` text.
        :param old_pkgbuild: the complete pre-change ``PKGBUILD`` text, or
            ``None`` for a first-seen package.
        :param maintainer: maintainer to attribute the analysis to.
        :param srcinfo: optional ``.SRCINFO`` text for the same package.
        :param last_modified: AUR ``LastModified`` in Unix seconds.
        :param first_submitted: AUR ``FirstSubmitted`` in Unix seconds.
        :param previous_modified: the previous observation's ``LastModified``
            in Unix seconds.
        :param record: persist the run as an observation and analysis
            history.  ``False`` keeps the call read-only.
        :returns: the analysis of the supplied text.
        :raises ValueError: an argument fails the API's input bounds.

        Example:
            .. code-block:: python

                from pathlib import Path

                from trustsight import TrustSight

                report = TrustSight().analyze_text(
                    "some-package",
                    Path("PKGBUILD").read_text(),
                )
        """
        from ..full_aur.analyze import analyze_package_text
        from ..schema import TemporalContext

        _validate_name(package)
        _validate_text(new_pkgbuild, name="new_pkgbuild")
        if old_pkgbuild is not None:
            _validate_text(old_pkgbuild, name="old_pkgbuild")
        _validate_text(maintainer, name="maintainer", maximum=MAX_API_NAME_BYTES)
        if srcinfo is not None:
            _validate_text(srcinfo, name="srcinfo")
        # The timestamps reached `TemporalContext` unchecked, so a caller
        # passing a date string - the obvious mistake, since every other
        # timestamp an AUR consumer holds is one - got a `TypeError` from
        # deep inside the temporal rules rather than an answer about the
        # argument they got wrong. Every other argument on this method is
        # validated at the boundary; these were the exception.
        for _name, _value in (("last_modified", last_modified),
                              ("first_submitted", first_submitted),
                              ("previous_modified", previous_modified)):
            if _value is not None:
                _validate_nonnegative(_value, name=_name)
        self._ensure_ready()
        fact = analyze_package_text(
            pkg_name=package,
            old_pkgbuild=old_pkgbuild,
            new_pkgbuild=new_pkgbuild,
            maintainer=maintainer,
            temporal=TemporalContext(
                last_modified=last_modified,
                first_seen=first_submitted,
                previous_modified=previous_modified,
                source="caller" if last_modified is not None else "unknown",
            ),
            srcinfo=srcinfo,
            record=record,
        )
        return _report_from_fact(fact)

    def analyze_diff(
        self,
        diff_text: str,
        *,
        package: str = "",
        post_pkgbuild: Optional[str] = None,
    ) -> Report:
        """Analyse a unified diff directly, with no git and no network.

        The analyzer's true input is a unified diff; the AUR/git machinery
        is a fetch adapter.  This entry point analyses a diff pasted from a
        bug report, a PR against its base, or a vendored PKGBUILD against
        upstream.  It runs the same pipeline stage the git path runs after
        diff production, with ``adapter="diff"`` in the report.

        *post_pkgbuild* is the post-diff PKGBUILD when the caller holds it;
        it sharpens the unresolved/parse-time analysis the way the git path
        uses the head recipe.  Without it, the diff's own post projection
        is the analysed surface.

        ``diff_truncated`` and the other coverage gaps apply with full
        force: pasted diffs are the most likely to be mangled.

        :param diff_text: the unified diff to analyse.
        :param package: optional package name used for attribution and
            package-scoped overrides.
        :param post_pkgbuild: optional complete post-diff ``PKGBUILD``; when
            supplied it sharpens the unresolved/parse-time analysis.
        :returns: the analysis of the supplied diff.
        :raises ValueError: an argument fails the API's input bounds.

        Example:
            .. code-block:: python

                from pathlib import Path

                from trustsight import TrustSight

                report = TrustSight().analyze_diff(
                    Path("change.diff").read_text(),
                )
        """
        from ..analysis.pipeline import scan_diff

        _validate_text(diff_text, name="diff_text")
        if package:
            _validate_name(package)
        if post_pkgbuild is not None:
            _validate_text(post_pkgbuild, name="post_pkgbuild")
        self._ensure_ready()
        fact = scan_diff(
            diff_text, package_name=package, current_text=post_pkgbuild,
        )
        fact.adapter = "diff"
        return _report_from_fact(fact)

    def verify_build(self, package: str, *, diff_text: str = "",
                     manifest: Optional[list] = None,
                     declared: Optional[dict] = None,
                     static_clean: Optional[bool] = None    ) -> dict:
        """The optional L9 build lane, off by default.

        When ``[verify] enabled`` is false, or the rootless container is
        unavailable, this returns ``l9_unavailable`` - a weight-0 boundary,
        never a clean or malicious verdict.  When enabled and given a
        manifest it inspects the artifact (A001-A008) without executing
        anything; the build that produces the manifest runs outside the
        static core.

        *static_clean* is the caller's L1-L8 outcome; when it and the L9
        findings disagree, the result carries ``l9_divergence`` - both
        profiles render, and L9 never edits the static verdict.

        :param package: package name the result is attributed to.
        :param diff_text: reserved for callers that keep the analysed diff;
            the manifest inspection does not read it.
        :param manifest: the artifact manifest to inspect, or ``None`` to
            report the lane as unavailable.
        :param declared: the package's declared artifact facts, used by the
            A-series comparisons.
        :param static_clean: the caller's L1-L8 outcome, or ``None`` when it
            was not computed.
        :returns: a dict with ``package``, ``status`` (``l9_unavailable`` or
            ``l9_analyzed``), ``findings`` and, on disagreement,
            ``l9_divergence``.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                result = TrustSight().verify_build(
                    "some-package",
                    manifest=manifest,
                    static_clean=True,
                )
                if result["status"] == "l9_unavailable":
                    print(result["reason"])
        """
        _validate_name(package)
        from ..config import load_config

        verify = (load_config().get("verify") or {})
        if not verify.get("enabled", False):
            return {
                "package": package, "status": "l9_unavailable",
                "reason": "the L9 build lane is disabled ([verify] enabled = false)",
                "findings": [],
            }
        from ..analysis.artifact import inspect_manifest

        if manifest is None:
            return {
                "package": package, "status": "l9_unavailable",
                "reason": "no artifact manifest was supplied and no sandbox ran",
                "findings": [],
            }
        findings = inspect_manifest(manifest, declared)
        strong = any(f.get("severity") in ("HIGH", "CRITICAL") for f in findings)
        result = {
            "package": package, "status": "l9_analyzed", "findings": findings,
        }
        if static_clean is not None and static_clean != (not strong):
            # Disagreement, either way: L1-L8 clean / L9 anomalous, or the
            # reverse.  Both profiles are the truth; L9 does not reweight.
            result["l9_divergence"] = True
        return result

    def review(
        self,
        *,
        packages: Optional[Sequence[str]] = None,
        limit: int = 0,
        repos: Optional[Sequence[str]] = None,
        foreign: bool = False,
        all_repos: bool = False,
        all_packages: bool = False,
        on_progress: Optional[ProgressHook] = None,
        on_warning: Optional[Callable[[str], None]] = None,
        depth: Optional[int] = None,
        deps: bool = False,
        record: bool = False,
    ) -> ReviewResult:
        """Review installed AUR packages: what ``trustsight review`` does.

        With no arguments this discovers installed foreign packages, works
        out which have a newer version in the AUR, and analyses those.
        Pass *packages* to review an explicit list instead and skip
        discovery entirely.

        Read-only by default: nothing is written, so repeated calls against
        the same database return the same reports.  ``record=True`` persists
        observations and analysis history.

        The first call with no local AUR metadata snapshot downloads one and
        reviews against it in the same invocation.

        :param limit: analyse at most this many packages (0 = no limit).
        :param repos: local repositories to scan, by name.
        :param foreign: include packages ``pacman -Qm`` reports.
        :param all_repos: auto-detect local repos from ``pacman.conf``.
        :param all_packages: review every discovered package, not only the
            ones with a newer AUR version.
        :param deps: review the AUR *dependencies* of the discovered
            packages instead of the packages themselves, as
            ``review --deps`` does.  Each report then carries
            :attr:`Report.required_by`.  Honours *depth* as the number of
            dependency levels to review.
        :returns: every report and every failure from the run.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                result = TrustSight().review(limit=10)
                for report in result.flagged:
                    print(report.package, report.verdict)
                for failure in result.failures:
                    print(failure.package, "NOT vetted:", failure.error)
        """
        from ..review import analyze_outdated_batch, dependency_entries, discover_packages

        _validate_limit(limit, name="limit", maximum=MAX_API_PACKAGES)
        if packages is not None:
            _validate_names(packages, name="packages", maximum=MAX_API_PACKAGES)
        if repos is not None:
            _validate_names(repos, name="repos", maximum=MAX_API_REPOS)

        self._ensure_ready()

        total_installed = 0
        if packages is not None:
            entries = [{"name": name, "current_version": ""} for name in packages]
        else:
            repos = list(repos or [])
            include_foreign = foreign
            if not repos and not all_repos and not foreign:
                discovery = self.config().get("discovery", {})
                repos = list(discovery.get("default_repos", []))
                include_foreign = discovery.get("include_foreign", False)
                all_repos = discovery.get("all_repos", False)
                if not repos and not all_repos and not include_foreign:
                    include_foreign = True

            discovered, total_installed = discover_packages(
                repos=repos,
                include_foreign=include_foreign,
                all_repos=all_repos,
                all_packages=all_packages,
                on_warn=on_warning,
            )
            if discovered is None:
                return ReviewResult(metadata_bootstrapped=True)
            entries = discovered

        required_by: dict[str, list[str]] = {}
        if deps:
            entries, required_by, _note = dependency_entries(
                entries, depth, self.config(), on_warning
            )
            # The dependencies are the subject now, so their own closure is
            # not walked again underneath them.
            depth = 0

        if limit:
            entries = entries[:limit]
        if not entries:
            return ReviewResult(total_installed=total_installed)

        # verbose=True keeps the underlying fact on each row, which is what
        # lets a review report carry everything an inspect report does.
        rows = analyze_outdated_batch(entries, _hook(on_progress), verbose=True,
                                      depth=depth, record=record)

        # Same field on every surface: the CLI attaches this to the row it
        # renders and serialises, so the API attaches it to the row it turns
        # into a Report.
        for row in rows:
            row["required_by"] = list(required_by.get(row.get("package"), ()))

        reports, failures = [], []
        for row in rows:
            if row.get("failed"):
                failures.append(FailedPackage(
                    package=row["package"],
                    old_version=row.get("old_version", ""),
                    new_version=row.get("new_version", ""),
                    error=row.get("error", ""),
                    error_type=row.get("error_type", ""),
                ))
            else:
                reports.append(_report_from_result(row))

        return ReviewResult(
            reports=tuple(reports),
            failures=tuple(failures),
            total_installed=total_installed,
        )

    # --- corpus ------------------------------------------------------

    def refresh_corpus(
        self,
        *,
        bootstrap: bool = False,
        resume: bool = False,
        export_path: Optional[str] = None,
        sign_key: Optional[str] = None,
        over_threshold: Optional[int] = None,
        since: Optional[int] = None,
    ) -> CycleReport:
        """Run one full-AUR corpus cycle: what ``trustsight full-aur`` does.

        Refreshes the AUR metadata snapshot, analyses what changed since
        the stored copy, runs the corpus-wide sweep and records the
        adoption feed. ``bootstrap=True`` permits the initial whole-AUR
        build when no snapshot exists; it takes hours. ``resume=True``
        continues an interrupted build.

        :param bootstrap: permit the initial whole-AUR build when no
            snapshot exists; it takes hours.
        :param resume: continue an interrupted bootstrap build.
        :param export_path: write the refreshed snapshot to this path.
        :param sign_key: sign the exported snapshot with this GPG key.
        :param over_threshold: the alerting bar for
            ``CycleReport.over_threshold``.  ``None`` uses the benign
            corpus's p95.
        :param since: a unix timestamp to replay change history from, one
            AUR day per cycle, or ``None`` for the normal delta.
        :returns: what the cycle added, changed, removed and flagged.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                cycle = TrustSight().refresh_corpus()
                print(cycle.processed, cycle.flagged)
        """
        from ..full_aur.pipeline import run_baseline_build

        self._ensure_ready()
        return _cycle_report(run_baseline_build(
            bootstrap=bootstrap, resume=resume, export_path=export_path, sign_key=sign_key,
            over_threshold=over_threshold, since=since,
        ))

    def watch(
        self,
        *,
        interval: Optional[int] = None,
        cycles: int = 0,
        over_threshold: Optional[int] = None,
        since: Optional[int] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Iterator[CycleReport]:
        """Yield one ``CycleReport`` per corpus cycle, forever by default.

        This is ``trustsight full-aur --watch`` as a generator: each cycle
        is exactly what :meth:`refresh_corpus` does once, and the loop adds
        repetition plus memory.  A cluster appears in ``new_alerts`` the
        first time it is seen and is then counted, not re-announced, so a
        quiet cycle yields a report with nothing new in it rather than the
        same forty-package adoption again.

        The generator sleeps between cycles, so it blocks the calling
        thread; stop it by breaking out of the loop or closing it.  State
        is durable at every yield: each cycle saves the snapshot and the
        resume file before it returns.

        :param interval: seconds between cycles.  ``None`` uses
            ``limits.watch_interval`` (3600).  Values below
            ``limits.watch_min_interval`` (60) are clamped up: a shorter
            interval only re-downloads a snapshot the AUR has not
            regenerated yet.
        :param cycles: stop after this many cycles (0 = until the caller
            stops iterating).
        :param over_threshold: the alerting bar for
            ``CycleReport.over_threshold``.  ``None`` uses the benign
            corpus's p95.
        :param since: a unix timestamp to replay change history from, one
            AUR day per cycle before joining the live stream, or ``None``
            for the normal delta.
        :returns: an iterator of one :class:`CycleReport` per cycle.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                for cycle in TrustSight().watch(cycles=2):
                    print(cycle.processed, cycle.flagged)
        """
        if interval is not None:
            _validate_nonnegative(interval, name="interval")
        _validate_nonnegative(cycles, name="cycles")

        def _run() -> Iterator[CycleReport]:
            from ..full_aur.pipeline import run_baseline_build, watch_interval_seconds

            self._ensure_ready()
            delay = watch_interval_seconds(interval)
            count = 0
            while True:
                yield _cycle_report(run_baseline_build(over_threshold=over_threshold,
                                                         since=since))
                count += 1
                if cycles and count >= cycles:
                    return
                sleep(delay)

        return _run()

    def import_baseline(self, path: str | Path, *, allow_unsigned: bool = False) -> None:
        """Import a signed baseline corpus artifact.

        Unsigned artifacts are rejected unless *allow_unsigned* is set,
        which is for local builds only: an unsigned baseline is data of
        unknown provenance being written into the database that every
        subsequent novelty judgement reads.

        :param path: baseline archive to import.
        :param allow_unsigned: accept an unsigned local build.  Never set
            this for an artifact downloaded from a release channel.
        :returns: None.  The import raises on any failure.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                TrustSight().import_baseline("baseline-seed.tar.gz")
        """
        from ..full_aur.export import import_baseline

        self._ensure_ready()
        import_baseline(str(path), allow_unsigned=allow_unsigned)

    def pivot(self, indicator: str, *, type: Optional[str] = None) -> PivotResult:
        """Find every corpus package referencing *indicator*.

        The inverse of a per-package finding: given a package name, domain
        or artifact hash, which packages touch it.  Reads only stored
        corpus material, never the network.

        :param indicator: a package name, domain or artifact hash.
        :param type: force the indicator type (``package``, ``domain`` or
            ``hash``) when the shape is ambiguous.
        :returns: which corpus packages reference *indicator*.
        :raises TrustSightError: the indicator type is unknown or the
            indicator could not be classified.
        :raises ValueError: the indicator is empty.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                result = TrustSight().pivot("evil.example")
                for match in result.matches:
                    print(match.package, match.surface)
        """
        from ..full_aur.pivot import pivot as _pivot
        from ..iocs import PIVOT_IOC_TYPES

        _validate_text(indicator, name="indicator", maximum=MAX_API_NAME_BYTES)
        if not indicator:
            raise ValueError("indicator must not be empty")
        self._ensure_ready()
        if type is not None and type not in PIVOT_IOC_TYPES:
            raise TrustSightError(
                f"unknown indicator type {type!r}; expected one of "
                f"{', '.join(sorted(PIVOT_IOC_TYPES))}"
            )
        result = _pivot(indicator, type=type)
        if result.get("error"):
            raise TrustSightError(result["error"])
        return PivotResult(
            indicator=result["indicator"],
            type=result["type"],
            listed=result.get("listed", False),
            confidence=result.get("confidence") or "",
            matches=tuple(
                PivotMatch(
                    package=m.get("package", ""),
                    surface=m.get("surface", ""),
                    detail=m.get("detail", ""),
                )
                for m in result.get("matches", [])
            ),
            sources=tuple(result.get("sources", [])),
        )

    # --- stored state ------------------------------------------------

    def history(
        self,
        package: str,
        *,
        limit: int = 20,
        with_rules: bool = False,
    ) -> list[HistoryEntry]:
        """Past analyses of *package*, newest first.

        Returns an empty list when the package has never been analysed:
        that is a fact about this database, not an error.

        :param package: package name to read.
        :param limit: maximum number of entries, newest first.
        :param with_rules: include the rule ids that fired in each entry.
        :returns: past analyses, newest first.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                for entry in TrustSight().history("some-package", limit=5):
                    print(entry.timestamp, entry.score, entry.risk)
        """
        from ..db import get_history, get_package_id, get_triggered_rules
        from ..scoring import stored_band
        from ..verdict import display_version

        _validate_limit(limit, name="limit", maximum=MAX_API_HISTORY)
        self._ensure_ready()
        pkg_id = get_package_id(package)
        if pkg_id is None:
            return []

        entries = []
        for row in get_history(pkg_id, limit=limit):
            rules = tuple(get_triggered_rules(row["id"])) if with_rules else ()
            entries.append(HistoryEntry(
                timestamp=row.get("timestamp", ""),
                old_version=display_version(row.get("old_version")),
                new_version=display_version(row.get("new_version")),
                score=row.get("final_score", 0),
                risk=stored_band(row)[0],
                triggered_rules=rules,
            ))
        return entries

    def packages(self, *, limit: int = 0) -> list[TrackedPackage]:
        """Every package in the database with its latest score.

        What ``trustsight list`` shows.

        :param limit: maximum number of packages to return (0 = all).
        :returns: one :class:`TrackedPackage` per tracked package.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                for pkg in TrustSight().packages(limit=10):
                    print(pkg.name, pkg.version, pkg.risk)
        """
        from ..db import get_all_packages, get_last_analysis
        from ..scoring import stored_band
        from ..verdict import display_version

        _validate_limit(limit, name="limit", maximum=MAX_API_PACKAGES)
        self._ensure_ready()
        rows = get_all_packages()
        if limit:
            rows = rows[:limit]

        out = []
        for pkg in rows:
            last = get_last_analysis(pkg["id"])
            score = last["final_score"] if last else None
            out.append(TrackedPackage(
                name=pkg["name"],
                version=display_version(pkg.get("current_version")),
                last_checked=pkg["last_checked"] or "",
                score=score,
                risk=stored_band(last, score)[0] if last else "",
                maintainer=pkg["current_maintainer"] or "",
            ))
        return out

    def forget(self, *packages: str) -> dict[str, dict]:
        """Delete tracked packages and all their history.

        Returns ``{package: {table: rows_deleted}}``.  A package that was
        not tracked maps to an empty dict.  This is not reversible: the
        observations it removes are what the novelty signals count.

        :param packages: package names to forget.
        :returns: per-package, per-table counts of what was deleted.
        :raises TrustSightError: a name is not a valid package name.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                deleted = TrustSight().forget("old-package")
                print(deleted["old-package"])
        """
        from ..db import forget_package

        self._ensure_ready()
        results: dict[str, dict] = {}
        for name in packages:
            try:
                results[name] = forget_package(name)
            except ValueError as exc:
                raise TrustSightError(str(exc)) from exc
        return results

    def prune(self, *, dry_run: bool = False) -> dict[str, dict]:
        """Forget every tracked package that no longer exists in the AUR.

        Set *dry_run* to see what would go without deleting it.

        :param dry_run: report what would be deleted without deleting it.
        :returns: per-package, per-table counts of what would be or was
            deleted.
        :raises TrustSightError: the AUR gave no authoritative answer
            (network failure, retry exhaustion, malformed reply), so which
            packages still exist could not be determined.  Deleting on a
            guess would forget the whole database over a network blip.

        Example:
            .. code-block:: python

                from trustsight import TrustSight

                would_go = TrustSight().prune(dry_run=True)
                print(sum(len(v) for v in would_go.values()), "rows")
        """
        from ..db import forget_prune, get_all_packages
        from ..discovery import get_existing_aur_package_names

        self._ensure_ready()
        names = [p["name"] for p in get_all_packages()]
        if not names:
            return {}
        existing = get_existing_aur_package_names(names)
        if existing is None:
            raise TrustSightError(
                "AUR RPC returned no data; cannot determine which packages "
                "still exist. Check your network connection and try again."
            )
        return forget_prune(existing, dry_run=dry_run)
