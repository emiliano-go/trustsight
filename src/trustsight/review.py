"""The review engine: discovery, prefetch and batch analysis.

This is what ``trustsight review`` does minus the terminal.  It lived in
``cli/review.py`` and could therefore only be driven by a typer callback,
which meant the public API would have had to import the CLI - and with it
typer and rich - to run the same flow.  Everything display-shaped stays in
``cli/review.py``; everything here talks through callbacks instead.

Callers: ``trustsight.cli.review`` (renders it) and ``trustsight.api``
(returns it).  Both must get the same results from the same inputs, so
neither owns a private copy of the pipeline.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout, as_completed
from typing import Callable, Optional

from .analysis import analyze_package
from .config import CONFIG_DIR, load_config
from .reporting import evaluate_fact, is_trivial
from .verdict import no_aur_change_note

log = logging.getLogger(__name__)

# (current, total, phase).  ``current`` of -1 means "indeterminate": the
# phase changed but there is nothing to count yet.
ProgressCallback = Callable[[int, int, str], None]


def _orphan_state(aur: Optional[dict]) -> Optional[bool]:
    """Whether the AUR reports this package orphaned, or None if unknown.

    The RPC omits ``Maintainer`` or sets it null for an orphan.  A missing
    metadata entry is None rather than False, because "we could not ask" and
    "it has a maintainer" are different facts and H086 needs to tell them
    apart.
    """
    if not aur:
        return None
    if "Maintainer" not in aur:
        return None
    return not aur.get("Maintainer")


def metadata_ttl_minutes() -> int:
    """Minutes a metadata snapshot may be used before it is refetched.

    ``0`` (or a negative or unparsable value) disables the refresh, which is
    the pre-0.13.2 behaviour: the snapshot is used for as long as it exists.
    """
    from .full_aur.metadata import DEFAULT_TTL_MINUTES

    cfg = load_config().get("discovery", {})
    try:
        configured = int(cfg.get("metadata_ttl_minutes", DEFAULT_TTL_MINUTES))
    except (TypeError, ValueError):
        return 0
    return max(0, configured)


def _humanised_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "of unknown age"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes old"
    if seconds < 172800:
        return f"{int(seconds // 3600)} hours old"
    return f"{int(seconds // 86400)} days old"


def _refreshed_metadata(meta, snapshot_time, meta_path, on_download, on_notice, on_warn,
                        force_refresh=False):
    """Return *meta*, refetched first if the snapshot has gone stale.

    A stale snapshot is not a degraded answer, it is a wrong one: every
    installed package resolves to the version the snapshot recorded, so a
    machine with pending AUR updates is told it has none.  The snapshot was
    downloaded once on first run and then reused forever, so this was every
    installation's steady state rather than an edge case.

    A refresh that fails keeps the old snapshot and warns, because the
    alternative - reporting nothing - is the same silent lie.
    """
    from .full_aur.metadata import fetch_metadata, save_metadata, snapshot_age_seconds

    ttl = metadata_ttl_minutes()
    age = snapshot_age_seconds(snapshot_time)

    if not force_refresh:
        if not ttl:
            if on_notice and age is not None:
                on_notice(
                    f"Using AUR metadata snapshot {_humanised_age(age)} "
                    "(auto-refresh disabled; set metadata_ttl_minutes > 0 "
                    "or use --refresh)."
                )
            return meta

        if age is not None and age < ttl * 60:
            return meta

    if on_notice:
        if force_refresh:
            on_notice(
                f"Refreshing AUR metadata snapshot (forced; was {_humanised_age(age)})."
            )
        else:
            on_notice(f"AUR metadata snapshot is {_humanised_age(age)}; refreshing.")

    try:
        fresh = fetch_metadata(on_progress=on_download) if on_download else fetch_metadata()
    except Exception as exc:
        # debug, not warning: an unreachable AUR is an ordinary condition,
        # and the handler prints a traceback at warning level - which would
        # bury the one line the user needs under a stack from urllib.
        log.debug("metadata refresh failed", exc_info=True)
        if on_warn:
            on_warn(
                f"could not refresh the AUR metadata snapshot ({exc}); the "
                f"snapshot in use is {_humanised_age(age)}, so a package "
                "updated since then will not be reported as outdated."
            )
        return meta

    if not fresh:
        # An empty dump would overwrite a usable snapshot with nothing and
        # then report every package as unknown.  Keep what works.
        if on_warn:
            on_warn(
                "the AUR metadata refresh returned no packages; keeping the "
                f"snapshot from {_humanised_age(age)}."
            )
        return meta

    save_metadata(fresh, path=meta_path)
    return fresh


def discover_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    all_packages: bool = False,
    on_warn: Optional[Callable[[str], None]] = None,
    on_download: Optional[Callable[[int, Optional[int]], None]] = None,
    on_notice: Optional[Callable[[str], None]] = None,
    force_refresh: bool = False,
) -> tuple[Optional[list[dict]], int]:
    """Find installed packages that have a newer version in the AUR.

    Returns ``(packages, total_installed)``.  ``packages`` is ``None`` when
    this call did nothing but download the first metadata snapshot: there
    was no prior copy to diff against, so there is no delta to report and
    the caller should say so and stop rather than print "nothing changed".

    *on_download* receives ``(bytes_so_far, total_bytes_or_None)`` during
    that first snapshot fetch; *on_notice* receives one-line status text.
    """
    repos = repos or []
    try:
        from .full_aur.metadata import (
            fetch_metadata,
            load_snapshot,
            save_metadata,
            snapshot_age_seconds,
        )
        from .discovery import _vercmp

        meta_path = CONFIG_DIR / "full-aur-meta.json"
        snapshot = load_snapshot(path=meta_path)
        if snapshot is None:
            meta = fetch_metadata(on_progress=on_download) if on_download else fetch_metadata()
            save_metadata(meta, path=meta_path)
            if on_notice:
                on_notice(
                    "Downloaded AUR metadata snapshot. Run again to review changes."
                )
            return None, 0

        meta, snapshot_time = snapshot
        meta = _refreshed_metadata(
            meta, snapshot_time, meta_path, on_download, on_notice, on_warn,
            force_refresh=force_refresh,
        )

        installed = get_installed_packages(
            repos, include_foreign, all_repos, all_packages, on_warn=on_warn
        )
        total_installed = len(installed)

        outdated = []
        show_unmatched = load_config().get("discovery", {}).get("show_unmatched", True)
        for pkg in installed:
            name = pkg["name"]
            aur = meta.get(name)
            latest_ver = aur.get("Version", "") if aur else ""
            if all_packages and aur is None and not show_unmatched:
                continue
            # H086: the AUR reports Maintainer=null for an orphan, and an
            # adoption is the June 2026 campaign's entry point.  Absent
            # metadata stays None: unknown is not "maintained".
            orphaned = _orphan_state(aur)
            if all_packages:
                pkg["latest_version"] = latest_ver or pkg["current_version"]
                if aur and isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
                pkg["aur_orphaned"] = orphaned
                outdated.append(pkg)
            elif latest_ver and _vercmp(pkg["current_version"], latest_ver) < 0:
                pkg["latest_version"] = latest_ver
                if isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
                pkg["aur_orphaned"] = orphaned
                outdated.append(pkg)

        return outdated, total_installed
    except Exception:
        log.warning("metadata-dump discovery failed, falling back to AUR RPC", exc_info=True)
        from .discovery import discover_packages as dp
        pkgs = dp(
            repos=repos,
            include_foreign=include_foreign,
            all_repos=all_repos,
            all_packages=all_packages,
            _warn_func=on_warn if repos else None,
        )
        total = 0
        if include_foreign:
            from .discovery import get_installed_foreign
            total = len(get_installed_foreign())
        return pkgs, total


def get_installed_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    all_packages: bool = False,
    on_warn: Optional[Callable[[str], None]] = None,
) -> list[dict]:
    from .discovery import get_installed_foreign, get_installed_from_repo
    from .discovery import get_local_repos_from_pacman_conf, _repo_exists

    repos = repos or []
    sources: set[tuple[str, str]] = set()

    if all_repos:
        for repo in get_local_repos_from_pacman_conf():
            sources.update(get_installed_from_repo(repo))

    if repos:
        for repo in repos:
            pkgs = get_installed_from_repo(repo)
            if not pkgs and on_warn:
                if _repo_exists(repo):
                    on_warn(f"repo '{repo}' exists but no packages from it are installed.")
                else:
                    on_warn(f"repo '{repo}' does not exist.")
            sources.update(pkgs)

    if include_foreign or (not repos and not all_repos):
        sources.update(get_installed_foreign())

    return [{"name": name, "current_version": ver} for name, ver in sources]


def dependency_entries(discovered, depth, config=None, on_warn=None):
    """Turn the discovered packages into the dependency set to review.

    Returns ``(entries, required_by, note)``. The roots are dropped: the
    request was for their dependencies, and a package that is both a root
    and somebody's dependency is already being reviewed under its own name.

    The closure is walked over metadata only - no analysis - so the cost of
    deciding *what* to review stays proportional to the graph rather than to
    the number of recipes in it.

    It lives here rather than in the CLI because the API offers the same
    review, and a field the API can carry (``Report.required_by``) but never
    populate is a field that does nothing.
    """
    config = config if config is not None else load_config()
    from .depth import default_metadata, dependency_closure, resolve_depth

    roots = [entry["name"] for entry in discovered]
    resolved = resolve_depth(depth, config)
    if resolved == 0:
        # `--deps --depth 0` asks for the dependencies of nothing.
        return [], {}, ""

    try:
        closure = dependency_closure(
            roots, depth=resolved, metadata=default_metadata()
        )
    except Exception as exc:  # metadata unavailable, RPC down
        log.warning("dependency closure failed", exc_info=True)
        if on_warn:
            on_warn(f"could not resolve the dependency closure ({exc})")
        return [], {}, ""

    installed = {}
    try:
        installed = {
            pkg["name"]: pkg.get("current_version", "")
            for pkg in get_installed_packages(include_foreign=True)
        }
    except Exception:
        log.debug("installed lookup failed for --deps", exc_info=True)

    entries = [
        {"name": name, "current_version": installed.get(name, "")}
        for name in closure.names
    ]
    note = closure.reason if closure.truncated else ""
    return entries, dict(closure.dependents), note


def default_workers() -> int:
    try:
        configured = int(load_config().get("limits", {}).get("workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 8


def prefetch_deadline() -> int:
    try:
        configured = int(load_config().get("limits", {}).get("prefetch_timeout", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 120


def prefetch(pkgs: list[dict], progress_callback: Optional[ProgressCallback] = None) -> dict[str, int]:
    from .fetcher import clone_or_fetch, last_fetch_time

    def fetch(entry: dict) -> tuple[str, int | None]:
        name = entry["name"]
        repo = clone_or_fetch(name, entry.get("last_modified"))
        hint = entry.get("last_modified")
        if hint is None:
            hint = last_fetch_time(repo)
        return name, hint

    hints: dict[str, int] = {}
    total = len(pkgs)
    deadline = prefetch_deadline()
    workers = max(1, min(default_workers(), total))
    # Not a `with` block: the context manager exit calls shutdown(wait=True),
    # which blocks on the fetches still running when the deadline fires - the
    # progress bar then sits frozen on the last package it painted for as long
    # as those fetches take.  Abandon them instead; analysis re-fetches what
    # the deadline cut off.
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(fetch, entry): entry["name"] for entry in pkgs}
        try:
            for done, future in enumerate(as_completed(futures, timeout=deadline), start=1):
                name = futures[future]
                if progress_callback:
                    progress_callback(done, total, f"Fetching {name}")
                try:
                    fetched, commit_time = future.result()
                except Exception:
                    log.warning("fetch of %s failed; will retry during analysis", name, exc_info=True)
                    continue
                if commit_time is not None:
                    hints[fetched] = commit_time
        except _FutureTimeout:
            log.warning(
                "prefetch timed out after %ss; remaining packages will fetch during analysis",
                deadline,
            )
            if progress_callback:
                progress_callback(-1, 0, "Prefetch timed out; continuing...")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return hints


def verdict_for(fact) -> str:
    return evaluate_fact(fact)["verdict"]


def is_trivial_update(fact, findings: list[dict]) -> bool:
    return is_trivial(fact, findings)


def analyze_outdated_batch(
    pkgs: list[dict],
    progress_callback: Optional[ProgressCallback] = None,
    verbose: bool = False,
    depth: Optional[int] = None,
) -> list[dict]:
    """Prefetch, analyse and summarise *pkgs*, one result dict per package.

    A package whose analysis raises is reported, not dropped: the result
    carries ``failed: True`` and a verdict saying it was NOT vetted, since
    silently omitting it reads as "nothing to see here".
    """
    hints = prefetch(pkgs, progress_callback)

    # One visited set for the whole batch, so a dependency shared by many
    # installed packages costs one clone and one analysis rather than twenty.
    depth_seen: set[str] = set()

    if progress_callback:
        progress_callback(-1, 0, "Reviewing packages...")

    def _pipeline_one(entry):
        name = entry["name"]
        try:
            fact = analyze_package(
                name,
                installed_version=entry.get("current_version"),
                upstream_mtime=hints.get(name),
                aur_orphaned=entry.get("aur_orphaned"),
                depth=depth,
                # Shared across roots: one dependency is analysed once even
                # when twenty installed packages all need it.
                _depth_seen=depth_seen,
            )
        except Exception as exc:
            log.warning("analysis of %s failed unexpectedly", name, exc_info=True)
            return ("fail", entry, None, None, exc)
        verdict = verdict_for(fact)
        return ("ok", entry, fact, verdict, None)

    total = len(pkgs)
    analysed_by_idx: dict[int, tuple] = {}
    failures: list[dict] = []

    with ThreadPoolExecutor(max_workers=default_workers()) as pool:
        futures = {pool.submit(_pipeline_one, entry): i for i, entry in enumerate(pkgs)}
        done_count = 0
        for future in as_completed(futures):
            idx = futures[future]
            result = future.result()
            status = result[0]
            entry = result[1]
            done_count += 1
            if progress_callback:
                phase = f"Reviewing {entry['name']}" if status == "ok" else f"Failed {entry['name']}"
                if verbose and status == "ok":
                    phase += "  [dim]analysed[/]"
                progress_callback(done_count, total, phase)

            if status == "fail":
                _, _, _, _, exc = result
                failures.append({
                    "package": entry["name"],
                    "old_version": entry.get("current_version", ""),
                    "new_version": entry.get("latest_version", ""),
                    "score": None,
                    "verdict": f"Analysis failed ({type(exc).__name__}): this package was NOT vetted.",
                    "risk": "Error",
                    "first_seen": False,
                    "failed": True,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                })
            else:
                _, _, fact, verdict, _ = result
                analysed_by_idx[idx] = (entry, fact, verdict)

    results = []
    for idx in range(total):
        item = analysed_by_idx.get(idx)
        if item is None:
            continue
        entry, fact, verdict = item

        evaluated = evaluate_fact(fact)
        evaluated["old_version"] = entry.get("current_version", "")
        evaluated["new_version"] = entry.get("latest_version", "")
        evaluated["aur_note"] = no_aur_change_note(fact)
        evaluated.pop("raw", None)
        evaluated.pop("fact", None)
        res = evaluated
        # B5: a suppression travels with the result unconditionally.  It used
        # to ride along only under --verbose, so the default JSON dropped it
        # silently, and a silent suppression is indistinguishable from a
        # missed detection - the one thing B5 exists to prevent.
        res["suppressed_rules"] = evaluated["suppressed_rules"]
        if verbose:
            fired = [
                {"rule_id": e.rule_id, "severity": e.severity}
                for e in fact.score_breakdown
                if e.weight > 0 or e.severity == "FATAL"
            ]
            res["triggered_rules"] = fired
            res["_verbose_fact"] = fact
        results.append(res)
    results.extend(failures)
    return results
