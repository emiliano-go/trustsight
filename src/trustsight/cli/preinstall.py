"""``trustsight preinstall``: a read-only remote scanner.

A thin alias of ``inspect`` for packages you have not installed yet: it never
installs anything, never prompts, and never encodes a verdict in its exit
status (B6 - 0 when the analysis completed, 2 when it could not).  It differs
from ``inspect`` only in that a package absent from the local pacman set is
accepted without ``--allow-uninstalled``, and the whole recipe is analysed for
that fresh package (there is no installed side to diff against).

Both this command and the ``trustsight-gate`` hook render the same analysis
body; the gate adds the human approval decision, the scanner does not.
"""

from __future__ import annotations

import json
from typing import Optional

import typer

from ..config import ensure_default_configs, load_config
from ..db import init_db, maybe_auto_import_seed
from ..safe_text import clean
from .display import _print_colored
from .inspect import _inspect_one, analyze_package

__all__ = ["register_commands"]


def register_commands(app: typer.Typer):
    @app.command("preinstall")
    def preinstall(
        packages: list[str] = typer.Argument(
            ..., help="Package name(s) to scan before installing."),
        depth: int = typer.Option(
            None, "--depth",
            help="AUR dependency levels to analyse: 0 off, 1 default, n levels, "
                 "-1 every level (bounded).",
        ),
        deep: Optional[bool] = typer.Option(
            None, "--deep/--no-deep",
            help="Deep analysis: full dependency depth, and the L9 build lane "
                 "when verify.enabled is set. Defaults to the deep config.",
        ),
        full_recipe: Optional[bool] = typer.Option(
            None, "--full-recipe/--no-full-recipe",
            help="Analyse the whole recipe. Default: whole recipe when the "
                 "package is not installed, the pending diff when it is.",
        ),
        verbose: bool = typer.Option(
            False, "--verbose", help="Show triggered rules and score breakdown"),
        score: bool = typer.Option(
            False, "--score", help="Show the aggregate trust score"),
        risk: bool = typer.Option(
            False, "--risk", help="Show the risk level"),
        json_output: bool = typer.Option(
            False, "--json", help="Output JSON (exit 0 on completion)"),
    ):
        """Scan remote (not-installed) AUR packages before you install them.

        Read-only: it never installs, builds, or executes a package. Exit 0 when
        the scan completed (whatever it found), 2 when it could not run.
        """
        ensure_default_configs()
        init_db()
        config = load_config()
        if config.get("seed", {}).get("auto_import", True):
            maybe_auto_import_seed(quiet=json_output, allow_release_fetch=True)

        from ..discovery import get_all_installed, get_aur_package_info

        try:
            local = get_all_installed()
        except Exception:  # noqa: BLE001 - a missing pacman is "not installed"
            local = {}

        deep_enabled = (deep if deep is not None
                        else bool((config.get("deep") or {}).get("enabled", False)))
        scan_depth = -1 if (deep_enabled and depth is None) else depth

        from ..analysis.deep import deep_decision

        bodies: list[dict] = []
        for package in packages:
            installed = local.get(package)
            try:
                info = get_aur_package_info([package])
            except Exception:  # noqa: BLE001 - network failure is handled below
                info = {}
            if package not in info and installed is None:
                msg = f"Package '{clean(package)}' not found in the AUR."
                if json_output:
                    typer.echo(json.dumps({"package": package, "error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2)

            analyse_full = (full_recipe if full_recipe is not None
                            else installed is None)
            try:
                fact = analyze_package(
                    package, depth=scan_depth, record=False,
                    full_recipe=bool(analyse_full))
            except Exception as exc:  # noqa: BLE001 - B6: could not run => 2
                msg = f"Analysis of '{clean(package)}' failed: {clean(str(exc))}"
                if json_output:
                    typer.echo(json.dumps({"package": package, "error": msg}))
                else:
                    _print_colored(msg, "red", stderr=True)
                raise typer.Exit(code=2) from exc

            body = _inspect_one(
                fact,
                show_score=score,
                show_risk=risk,
                verbose=verbose,
                json_output=json_output,
            )
            if body is not None:
                decision = deep_decision(
                    config, getattr(fact, "final_score", None),
                    explicit=bool(deep))
                if decision["triggered"]:
                    l9 = None
                    if decision["l9_requested"]:
                        try:
                            from ..api import TrustSight

                            static_clean = not any(
                                e.severity in ("FATAL", "CRITICAL", "HIGH")
                                for e in fact.score_breakdown)
                            l9 = TrustSight().verify_build(
                                package, static_clean=static_clean)
                        except Exception as exc:  # noqa: BLE001 - lane optional
                            l9 = {"status": "l9_unavailable",
                                  "reason": f"{type(exc).__name__}: {exc}"}
                    else:
                        l9 = {"status": "l9_unavailable",
                              "reason": "verify lane disabled"}
                    body["deep"] = {**decision, "l9": l9}
                bodies.append(body)
            elif deep_enabled and not json_output:
                _print_colored(
                    "Deep analysis: full dependency closure; the L9 lane runs only "
                    "when verify.enabled is set.", "blue")

        if json_output:
            payload = bodies[0] if len(bodies) == 1 else bodies
            typer.echo(json.dumps(payload, indent=2))
