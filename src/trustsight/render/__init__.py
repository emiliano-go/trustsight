"""Rich rendering, isolated in the render sandbox.

Every Rich construct lives under this package.  The parent sends a named
operation and plain JSON; this package turns it into text.  Nothing here
touches the database, the network or the filesystem.
"""

from __future__ import annotations

#: op -> (module, function).  A new render path is a reviewed entry here.
OPS = {
    "review_results": ("trustsight.render.review", "render_results"),
    "print_colored": ("trustsight.render.display", "print_colored"),
    "inspect_panel": ("trustsight.render.inspect", "render_panel"),
    "inspect_history_panel": ("trustsight.render.inspect", "render_history_panel"),
    "rules_table": ("trustsight.render.tables", "rules_table"),
    "list_table": ("trustsight.render.tables", "list_table"),
    "history_table": ("trustsight.render.tables", "history_table"),
    "config_tables": ("trustsight.render.tables", "config_tables"),
    "seed_info_table": ("trustsight.render.tables", "seed_info_table"),
    "seed_stats_tables": ("trustsight.render.tables", "seed_stats_tables"),
    "ioc_sources_table": ("trustsight.render.tables", "ioc_sources_table"),
    "ioc_list_table": ("trustsight.render.tables", "ioc_list_table"),
    "override_tables": ("trustsight.render.tables", "override_tables"),
    "override_wizard_table": ("trustsight.render.tables", "override_wizard_table"),
    "pivot_table": ("trustsight.render.tables", "pivot_table"),
    "anergic_table": ("trustsight.render.tables", "anergic_table"),
    "property_transitions_table": ("trustsight.render.tables", "property_transitions_table"),
    "lint_table": ("trustsight.render.tables", "lint_table"),
    "status_table": ("trustsight.render.tables", "status_table"),
    "seed_imported_table": ("trustsight.render.tables", "seed_imported_table"),
    "sync_result": ("trustsight.render.tables", "sync_result"),
    "sync_wizard_summary": ("trustsight.render.tables", "sync_wizard_summary"),
    "sync_menu": ("trustsight.render.tables", "sync_menu"),
    "progress_start": ("trustsight.render.progress", "start"),
    "progress_update": ("trustsight.render.progress", "update"),
    "progress_stop": ("trustsight.render.progress", "stop"),
}
