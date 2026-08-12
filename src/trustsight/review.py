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


def discover_packages(
    repos: Optional[list[str]] = None,
    include_foreign: bool = False,
    all_repos: bool = False,
    all_packages: bool = False,
    on_warn: Optional[Callable[[str], None]] = None,
    on_download: Optional[Callable[[int, Optional[int]], None]] = None,
    on_notice: Optional[Callable[[str], None]] = None,
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
        from .full_aur.metadata import fetch_metadata, load_metadata, save_metadata
        from .discovery import _vercmp

        meta_path = CONFIG_DIR / "full-aur-meta.json"
        meta = load_metadata(path=meta_path)
        if meta is None:
            meta = fetch_metadata(on_progress=on_download) if on_download else fetch_metadata()
            save_metadata(meta, path=meta_path)
            if on_notice:
                on_notice(
                    "Downloaded AUR metadata snapshot. Run again to review changes."
                )
            return None, 0

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
            if all_packages:
                pkg["latest_version"] = latest_ver or pkg["current_version"]
                if aur and isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
                outdated.append(pkg)
            elif latest_ver and _vercmp(pkg["current_version"], latest_ver) < 0:
                pkg["latest_version"] = latest_ver
                if isinstance(aur.get("LastModified"), int):
                    pkg["last_modified"] = aur["LastModified"]
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
) -> list[dict]:
    """Prefetch, analyse and summarise *pkgs*, one result dict per package.

    A package whose analysis raises is reported, not dropped: the result
    carries ``failed: True`` and a verdict saying it was NOT vetted, since
    silently omitting it reads as "nothing to see here".
    """
    hints = prefetch(pkgs, progress_callback)

    if progress_callback:
        progress_callback(-1, 0, "Reviewing packages...")

    def _pipeline_one(entry):
        name = entry["name"]
        try:
            fact = analyze_package(name, installed_version=entry.get("current_version"), upstream_mtime=hints.get(name))
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
