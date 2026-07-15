from .db import get_connection
from .schema import NoveltyContext


def check_url_novelty(url: str, package_id: int) -> tuple[bool, bool]:
    with get_connection() as conn:
        cur = conn.cursor()

        pkg_row = cur.execute(
            """SELECT 1 FROM source_urls
               WHERE url = ? AND first_seen_package_id = ?""",
            (url, package_id),
        ).fetchone()
        url_first_package = pkg_row is None

        global_row = cur.execute(
            "SELECT id, total_uses FROM source_urls WHERE url = ?", (url,)
        ).fetchone()
        url_first_global = global_row is None

        if url_first_global:
            cur.execute(
                """INSERT INTO source_urls (url, first_seen_package_id, first_seen_globally_timestamp, total_uses)
                   VALUES (?, ?, datetime('now'), 1)""",
                (url, package_id),
            )
        else:
            cur.execute(
                "UPDATE source_urls SET total_uses = total_uses + 1, last_seen_timestamp = datetime('now') WHERE id = ?",
                (global_row[0],),
            )

        conn.commit()

    return url_first_package, url_first_global


def check_maintainer_novelty(maintainer_name: str, package_id: int) -> bool:
    with get_connection() as conn:
        cur = conn.cursor()

        existing = cur.execute(
            """SELECT id FROM maintainers
               WHERE name = ? AND first_seen_package_id = ?""",
            (maintainer_name, package_id),
        ).fetchone()

        if existing is None:
            cur.execute(
                "INSERT INTO maintainers (name, first_seen_package_id) VALUES (?, ?)",
                (maintainer_name, package_id),
            )
            conn.commit()
            return True

    return False


def build_novelty_context(
    added_urls: list[str],
    package_id: int,
    maintainer: str = "",
) -> NoveltyContext:
    ctx = NoveltyContext()

    if maintainer:
        ctx.maintainer_first_seen_for_this_package = check_maintainer_novelty(
            maintainer, package_id
        )

    for url in added_urls:
        first_for_pkg, first_global = check_url_novelty(url, package_id)
        if first_for_pkg:
            ctx.url_first_seen_in_this_package = True
        if first_global:
            ctx.url_first_seen_globally = True

    return ctx