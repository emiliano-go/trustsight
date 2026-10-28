"""Watch-loop implementation, using the facade for patchable globals."""

import os
import signal as _signal
import threading
import time
from typing import Callable, Optional

from ._pipeline_helpers import CycleResult


def _pipeline():
    from . import pipeline
    return pipeline


def run_watch(
    interval: Optional[int] = None,
    cycles: int = 0,
    json_output: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    depth: Optional[int] = None,
    notify_url: Optional[str] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
    auto_pull_baselines: bool = False,
    auto_pull_iocs: bool = False,
    auto_pull_watchlists: bool = False,
) -> list[CycleResult]:
    """Run corpus cycles on an interval until interrupted.

    Each cycle is exactly what ``run_baseline_build`` does once: refresh
    the metadata snapshot, analyse what changed, run the Class D sweep and
    record the adoption feed.  What ``--watch`` adds is repetition and
    memory - a cluster is announced the first time it is seen and then
    counted, not re-announced, so the second cycle of a quiet night prints
    nothing rather than the same forty-package adoption again.

    ``SIGTERM``/``SIGINT`` set a stop event.  The current package finishes,
    the resume file and WAL are saved, and the loop exits without starting
    another cycle.  State is durable at every cycle boundary, so a crash
    loses at most the cycle in flight.
    """
    delay = _pipeline().watch_interval_seconds(interval)
    _log = _pipeline()._logger(json_output)
    results: list[CycleResult] = []
    stop = threading.Event()
    previous_handlers = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (_signal.SIGTERM, _signal.SIGINT):
            try:
                previous_handlers[sig] = _signal.getsignal(sig)
                _signal.signal(sig, lambda *_: stop.set())
            except (OSError, ValueError):
                pass

    from .. import __version__
    from ..db import get_db_path
    from . import watch_state

    _log(
        f"trustsight {__version__} watching the AUR: one cycle every {delay}s"
        + (f", {cycles} cycle(s)" if cycles else ", until interrupted")
    )
    try:
        _log(f"  database: {get_db_path()}")
    except Exception:  # noqa: BLE001 - the banner must never fail the watch
        pass
    try:
        from ..notify import notify_url as _configured_notify_url

        _effective = notify_url or _configured_notify_url()
        _log(f"  alert webhook: {'configured' if _effective else 'none'}")
    except Exception:  # noqa: BLE001
        pass
    # Retry anything a previous run could not deliver before spending the
    # next interval asleep.
    try:
        from ..notify import flush_outbox

        flush_outbox(notify_url)
    except Exception as exc:  # noqa: BLE001 - delivery is best effort
        _log(f"  pending alerts not flushed: {exc}")
    if not os.environ.get("TRUSTSIGHT_NO_SYNC_RULES", "").strip():
        try:
            from ..config import drifted_shipped_rules, sync_rules

            added, updated = sync_rules(update_outdated=True)
            if added or updated:
                _log(f"  ruleset synced: {len(added)} added, {len(updated)} updated")
            remaining = drifted_shipped_rules()
            if remaining:
                _log(f"  ruleset still drifted (user edits kept): {remaining}")
        except Exception as exc:  # noqa: BLE001 - never fail the watch over this
            _log(f"  ruleset sync skipped: {exc}")
    try:
        watch_state.record_start(delay)
    except Exception:
        pass

    def _sleep(seconds: float) -> None:
        if stop.is_set():
            return
        if sleep is time.sleep:
            stop.wait(seconds)
        else:
            sleep(seconds)

    attempts = 0
    try:
        while not stop.is_set():
            try:
                result = _pipeline().run_baseline_build(
                    json_output=json_output, depth=depth,
                    over_threshold=over_threshold, since=since,
                    should_stop=stop.is_set,
                )
                try:
                    watch_state.record_success()
                except Exception:
                    pass
            except Exception as exc:
                attempts += 1
                try:
                    failures = watch_state.record_failure(str(exc))
                except Exception:
                    failures = 0
                _log(f"Cycle failed ({exc}); retrying in {delay}s")
                if watch_state.should_notify_failure(failures):
                    try:
                        from ..notify import notify_watch_failure

                        if notify_watch_failure(
                            {"consecutive_failures": failures,
                             "last_error": str(exc)}, notify_url
                        ):
                            _log("  failure heartbeat delivered")
                    except Exception as notify_exc:  # noqa: BLE001
                        _log(f"  failure heartbeat skipped: {notify_exc}")
                if cycles and attempts >= cycles:
                    break
                _sleep(delay)
                continue
            attempts = 0
            if result.refused:
                from .metadata import load_metadata

                if load_metadata(slim=True) is None and _pipeline()._since_cursor() is None:
                    try:
                        watch_state.record_failure("no corpus snapshot")
                    except Exception:
                        pass
                    _log(
                        "No corpus snapshot yet; the watch has nothing to "
                        "diff against. Run 'trustsight full-aur --bootstrap' "
                        "first so an initial snapshot exists."
                    )
                    results.append(result)
                    break
                try:
                    watch_state.record_failure("cycle did no work")
                except Exception:
                    pass
                _log(f"Cycle did no work; retrying in {delay}s")
                _sleep(delay)
                continue
            results.append(result)
            if result.new_alerts:
                _log(f"{len(result.new_alerts)} new alert(s) this cycle")
                for package, rule_id in result.new_alerts:
                    _log(f"  {rule_id}  {package}")
            elif result.cluster_findings:
                _log("No new alerts; every cluster this cycle was already reported")
            from ..notify import maybe_heartbeat, maybe_notify

            if maybe_notify(result, notify_url):
                _log("  alert webhook delivered")
            elif maybe_heartbeat(result, notify_url):
                _log("  heartbeat delivered")
            if auto_pull_baselines or auto_pull_iocs or auto_pull_watchlists:
                from ..channels import auto_pull

                for note in auto_pull(
                    baselines=auto_pull_baselines, iocs=auto_pull_iocs,
                    watchlists=auto_pull_watchlists,
                ):
                    _log(f"  {note}")
            if stop.is_set():
                break
            if cycles and len(results) >= cycles:
                break
            _sleep(2 if result.backfilling else delay)
    except KeyboardInterrupt:
        stop.set()
    finally:
        for sig, handler in previous_handlers.items():
            try:
                _signal.signal(sig, handler)
            except (OSError, ValueError):
                pass
    _log(f"Watch stopped after {len(results)} cycle(s)")
    return results
