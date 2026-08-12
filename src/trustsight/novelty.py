import re
from datetime import datetime, timezone

from .config import DEFAULT_KNOWN_SUFFIXES, load_naming
from .db import (
    _get_salt,
    _hash_maintainer_value,
    dependency_observation_count,
    dependency_table_populated,
    effective_observation_count,
    get_connection,
    top_dependency_names,
    top_dependency_pairs,
)
from .deps import normalize_dependency
from .schema import NoveltyContext

_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,}")
_HASH_RE = re.compile(r"(?<=[./])[a-f0-9]{7,40}(?=[./]|$)", re.IGNORECASE)
_DATE_RE = re.compile(r"\d{4}[-_]\d{2}[-_]\d{2}")
_TRAILING_RE = re.compile(r"/+$")


def normalize_url(url: str) -> str:
    """Normalize a URL into a version-stable template for novelty dedup.

    Strips version numbers, hashes, and dates so that routine bumps
    (e.g. ``v2.0.0`` → ``v2.0.1``) do not generate false novelty signals.
    """
    n = url
    n = _VERSION_RE.sub("0", n)
    n = _HASH_RE.sub("HASH", n)
    n = _DATE_RE.sub("DATE", n)
    n = _TRAILING_RE.sub("", n)
    return n


def is_dependency_novel(name: str) -> bool:
    """True when *name* has never been observed anywhere in the AUR.

    Returns False when the dependency corpus has not been seeded.  Without
    that guard a fresh install has an empty table, every dependency looks
    novel, and D001 fires on every package it sees.
    """
    if not dependency_table_populated():
        return False
    normalized = normalize_dependency(name)
    if not normalized:
        return False
    return dependency_observation_count(normalized) == 0


def _damerau_levenshtein(a: str, b: str, limit: int) -> int:
    """Edit distance including transpositions, abandoned once past *limit*."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + cost)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[len(b)]


def typosquat_target(name: str, candidates: list[str] | None = None) -> str | None:
    """Return the popular package *name* appears to impersonate, if any.

    Only ever called for a name D001 has already found to be globally
    unknown, which is what makes a runtime edit-distance check affordable
    and correct.  A precomputed pair table cannot work here: any table
    built from existing package names can only contain names that must
    *not* fire, while the names that should fire do not exist yet.

    The threshold scales with length because short names sit close to many
    unrelated real packages (``yay`` is one edit from ``yak``, ``yam``,
    ``jay``, and ``may``).
    """
    if len(name) < 4:
        return None
    limit = 1 if len(name) < 8 else 2
    if candidates is None:
        candidates = top_dependency_names()
    best: tuple[int, str] | None = None
    for candidate in candidates:
        if candidate == name or abs(len(candidate) - len(name)) > limit:
            continue
        distance = _damerau_levenshtein(name, candidate, limit)
        if distance <= limit and (best is None or distance < best[0]):
            best = (distance, candidate)
            if distance == 1:
                break
    return best[1] if best else None


# Suffixes that denote expected package variants (fork, build, packaging mode)
# rather than typosquats.  Stripped before edit-distance comparison so that
# ``foo-git``, ``foo-bin``, ``foo-lts`` are never confused with the real ``foo``.
# Lived in code as ``_KNOWN_SUFFIXES``; now ships in naming.toml.
def _known_suffixes() -> tuple[str, ...]:
    suffixes = load_naming().get("naming", {}).get("known_suffixes")
    return tuple(suffixes) if suffixes else DEFAULT_KNOWN_SUFFIXES


def _strip_variant_suffix(name: str) -> str:
    """strip known variant suffixes like -git or -bin from a package name"""
    for s in _known_suffixes():
        if name.endswith(s):
            return name[: -len(s)]
    return name


def package_typosquat_target(pkg_name: str) -> str | None:
    """Return a far-more-popular package *pkg_name* appears to squat, or None.

    Asymmetric: only fires when the candidate is *much* more popular
    (10x+ observation count), so legitimate variants and forks that have
    grown their own reputation are never flagged.
    """
    if len(pkg_name) < 4:
        return None
    base = _strip_variant_suffix(pkg_name)
    pkg_pop = dependency_observation_count(pkg_name)

    # The popularity of every candidate arrives with the candidate list.
    # Asking per name meant one database round-trip each, which for the
    # default 5000-name list dominated the entire analysis.
    threshold = pkg_pop * 10
    limit = 1 if len(pkg_name) < 8 else 2
    filtered: list[str] = []
    for cand, cand_pop in top_dependency_pairs():
        # Edit distance cannot bridge a length gap wider than the limit, so
        # discarding those here keeps the comparison loop small.
        if abs(len(cand) - len(pkg_name)) > limit:
            continue
        if cand_pop < threshold:
            continue
        if cand == pkg_name or _strip_variant_suffix(cand) == base:
            continue
        filtered.append(cand)

    if not filtered:
        return None

    return typosquat_target(pkg_name, filtered)


def check_url_novelty(url: str, package_id: int) -> tuple[bool, bool]:
    """Record a URL in the novelty database and return whether it is novel for the package and globally"""
    nurl = normalize_url(url)
    with get_connection() as conn:
        cur = conn.cursor()

        pkg_row = cur.execute(
            """SELECT 1 FROM source_urls
               WHERE url = ? AND first_seen_package_id = ?""",
            (nurl, package_id),
        ).fetchone()
        url_first_package = pkg_row is None

        global_row = cur.execute(
            "SELECT id, total_uses FROM source_urls WHERE url = ?", (nurl,)
        ).fetchone()
        url_first_global = global_row is None

        if url_first_global:
            cur.execute(
                """INSERT INTO source_urls (url, first_seen_package_id, first_seen_globally_timestamp, total_uses)
                   VALUES (?, ?, datetime('now'), 1)""",
                (nurl, package_id),
            )
        else:
            cur.execute(
                "UPDATE source_urls SET total_uses = total_uses + 1, last_seen_timestamp = datetime('now') WHERE id = ?",
                (global_row[0],),
            )

        conn.commit()

    return url_first_package, url_first_global


def check_maintainer_novelty(maintainer_name: str, package_id: int) -> bool:
    """Record a maintainer in the novelty database and return whether it is novel for the package"""
    if not maintainer_name:
        return False
    with get_connection() as conn:
        cur = conn.cursor()

        salt = _get_salt(conn)
        if salt:
            name_hash = _hash_maintainer_value(maintainer_name, salt)
            existing = cur.execute(
                """SELECT 1 FROM package_maintainers_hashed
                   WHERE name_hash = ? AND package_id = ?""",
                (name_hash, package_id),
            ).fetchone()

            if existing is None:
                now = datetime.now(timezone.utc).isoformat()
                cur.execute(
                    """INSERT INTO package_maintainers_hashed
                       (name_hash, email_hash, package_id, first_seen)
                       VALUES (?, NULL, ?, ?)""",
                    (name_hash, package_id, now),
                )
                conn.commit()
                return True
        else:
            # No salt yet: fall back to the legacy plaintext table so the
            # first-seen-for-this-package semantics stay intact.
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
    """Build a NoveltyContext by checking URL and maintainer novelty"""
    ctx = NoveltyContext()

    # Read maturity before this analysis is recorded, so a package is
    # never counted as an observation of itself.  Falls back to a seeded
    # bootstrap count when there is no real history yet.
    ctx.observation_count = effective_observation_count()

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
