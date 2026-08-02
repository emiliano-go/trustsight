import re

from ..deps import _strip_comment
from ..differ import extract_source_array_urls
from ..novelty import normalize_url
from ..rules import _classify_enclosing_function
from ..tokenizer import join_line_continuations, resolve_added_lines
from .base import _experimental_enabled


_CRITICAL_FUNCTIONS = ("build", "prepare", "check", "package")

_INSTALL_HOOKS = (
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

_HOOK_EXEC_RE = re.compile(
    r"\b(?:eval|bash\s+-c|sh\s+-c|source\s+/|systemctl\s+enable|"
    r"chmod\s+[0-7]*[2467][0-7]{3}|chmod\s+[ugoa]*\+s|useradd|usermod|visudo)\b",
    re.IGNORECASE,
)

_UNTRUSTED_PATCH_RE = re.compile(
    r"(?:patch\b|git\s+apply\b)[^|;&]*?"
    r"(<\([^)]*\)"
    r"|https?://[^\s'\"]+"
    r"|[<\s-][ip]?\s*['\"]?/(?!usr/bin/patch)[^\s'\"$]+\.(?:patch|diff))",
    re.IGNORECASE,
)

_NETWORK_FETCH_RE = re.compile(
    r"(?:curl|wget|aria2c|git\s+clone|svn\s+(?:co|checkout)|"
    r"python\s+-c\s+.*urllib|python\s+-m\s+http)\b[^|;&]*?"
    r"(https?://[^\s|;&'\"\)]+)",
    re.IGNORECASE,
)

_FOREIGN_PKG_RE = re.compile(
    r"\b(?:pip|pip3)\s+install\b|"
    r"\bnpm\s+(?:install|add)\b|"
    r"\bbun\s+(?:install|add)\b|"
    r"\bpnpm\s+(?:install|add)\b|"
    r"\byarn\s+(?:install|add)\b|"
    r"\bcargo\s+install\b|"
    r"\bgem\s+install\b|"
    r"\bgo\s+install\b|"
    r"\bdnf\s+install\b|"
    r"\byum\s+install\b|"
    r"\bpacman\s+-[SU]\b|"
    r"\bapt(?:-get)?\s+install\b|"
    r"\bmake\s+install\b(?!\s+DESTDIR)",
    re.IGNORECASE,
)

_OBFUSCATION_PATTERNS_RE = [
    re.compile(p) for p in (
        r"base64.*(?:-d|--decode)",
        r"printf\s+['\"]\\x",
        r"\$\(|`",
        r"\beval\b",
        r"\|.*(?:bash|sh|zsh)\b",
        r"(?:bit\.ly|t\.co|tinyurl|shorturl|ow\.ly|is\.gd)",
        r"wget\s+-q\s+-O\s*-\s*\|",
        r"\$\{[a-zA-Z_][a-zA-Z0-9_]*\}.*(?:curl|wget|bash|sh)",
        # June-W3 campaign markers (confirmed campaign indicators):
        # ANSI-C quoting, variable indirection, empty-quote concatenation.
        r"\$'",
        r"\$\{!",
        r"(?<=\w)''(?=\w)",
    )
]

# R082 composition: a dense obfuscated line that reconstructs to an
# executable action is HIGH, not MEDIUM.  The action shapes mirror what
# R081 (foreign package manager), R003/R043 (decode-and-pipe) and R039
# (eval of dynamic content) detect on reconstructed text.
_RECONSTRUCTS_TO_ACTION_RE = re.compile(
    _FOREIGN_PKG_RE.pattern
    + r"|"
    r"(?:base64|xxd|uudecode)\b[^|]*\|[^|]*(?:bash|sh|zsh|dash)\b"
    + r"|"
    r"\beval\b"
    + r"|"
    r"(?:curl|wget)\b[^|;]*\|(?:bash|sh|zsh|dash)\b",
    re.IGNORECASE,
)


def _reconstructs_to_action(body: str) -> bool:
    """True when *body* (already resolved and reconstructed) reveals an
    executable action rather than inert obfuscation."""
    return bool(_RECONSTRUCTS_TO_ACTION_RE.search(body))


def reconstructs_to_js_pm_install(text: str) -> bool:
    return bool(_FOREIGN_PKG_RE.search(text))


def reconstructs_to_decode_pipe_sh(text: str) -> bool:
    return bool(
        re.search(
            r"(?:base64|xxd|uudecode)\b[^|]*\|[^|]*(?:bash|sh|zsh|dash)\b",
            text, re.IGNORECASE,
        )
    )


def reconstructs_to_eval_of_decoded(text: str) -> bool:
    return bool(re.search(r"\beval\b", text, re.IGNORECASE))

_ENV_SUBVERSION_HIGH_RE = re.compile(
    r"\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*(?:\+?=)",
)
_ENV_SUBVERSION_MED_RE = re.compile(
    r"\b(?:CFLAGS|LDFLAGS|MAKEFLAGS|PATH)\s*(?:\+?=)",
)


def _build_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)

    high_found = False
    med_found = False
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
            continue
        body = _strip_comment(line)
        if _ENV_SUBVERSION_HIGH_RE.search(body):
            high_found = True
        if _ENV_SUBVERSION_MED_RE.search(body):
            med_found = True
    if high_found:
        add("R070", "Build Environment Subversion", "HIGH", "build",
            "LD_PRELOAD or LD_LIBRARY_PATH set inside a build function",
            detail="LD_PRELOAD or LD_LIBRARY_PATH set inside a build function")
    elif med_found:
        add("R070", "Build Environment Subversion", "MEDIUM", "build",
            "CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function",
            detail="CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function")

    wanted = ({r for r in ("R060", "R061", "R062", "R063", "R064")
               if _experimental_enabled(config, r)}
              | {"R081", "R082"})
    if not wanted:
        return
    wants_060 = "R060" in wanted
    wants_061 = "R061" in wanted

    touched = sorted({
        fn for i, line in enumerate(lines)
        if line[:1] in ("+", "-")
        and (fn := enclosing.get(i)) in _CRITICAL_FUNCTIONS
    })
    if wants_060 and touched:
        add("R060", "Critical Build Function Modified", "INFO", "build",
            f"diff modifies {', '.join(f'{f}()' for f in touched)}",
            touched=", ".join(touched))

    if wants_061:
        declared = {normalize_url(u) for u in extract_source_array_urls(diff_text)}
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            for match in _NETWORK_FETCH_RE.finditer(line):
                url = match.group(1)
                if normalize_url(url) not in declared:
                    add("R061", "Hidden Network Fetch In Build", "HIGH", "network",
                        f"{enclosing[i]}() downloads {url}, which is not in source=()",
                        position=enclosing[i], url=url)
                    break
            else:
                continue
            break

    if "R062" in wanted:
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _INSTALL_HOOKS:
                continue
            body = _strip_comment(line)
            if _NETWORK_FETCH_RE.search(body) or _HOOK_EXEC_RE.search(body):
                add("R062", "Install Hook Fetches Or Executes", "HIGH", "installer",
                    f"{enclosing[i]}() runs as root and contains: {body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                break

    if "R063" in wanted:
        declared_urls = {normalize_url(u) for u in extract_source_array_urls(diff_text)}
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            match = _UNTRUSTED_PATCH_RE.search(_strip_comment(line))
            if match:
                patch_src = match.group(1).strip()
                # Skip URL-based patches that are also declared in source=()
                if patch_src.startswith("http") and normalize_url(patch_src) in declared_urls:
                    continue
                add("R063", "Patch Applied From Outside The Build Tree", "HIGH", "integrity",
                    f"{enclosing[i]}() applies a patch from {patch_src[:70]}",
                    position=enclosing[i], patch_src=patch_src[:70])
                break

    if "R064" in wanted:
        before = extract_source_array_urls(diff_text, side="before")
        after = extract_source_array_urls(diff_text, side="after")
        for url in sorted(before):
            if not url.startswith("https://"):
                continue
            if url.replace("https://", "http://", 1) in after:
                add("R064", "Source URL Downgraded To HTTP", "MEDIUM", "network",
                    f"source URL downgraded from https to http: {url[:70]}",
                    url=url[:70])
                break

    if "R081" in wanted:
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _INSTALL_HOOKS:
                continue
            body = _strip_comment(line)
            if _FOREIGN_PKG_RE.search(body):
                add("R081", "Foreign Package Manager In Install Hook", "HIGH", "installer",
                    f"{enclosing[i]}() invokes foreign package manager: {body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                break

    if "R082" in wanted:
        # Density is measured on the raw line: reconstruction removes the
        # markers, so counting on resolved text would miss the campaign.
        # The composed HIGH requires the reconstructed line to reveal an
        # executable action (R117 composition).
        raw_lines = join_line_continuations(diff_text.splitlines())
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            raw_body = _strip_comment(raw_lines[i])
            body = _strip_comment(line)
            count = sum(1 for p in _OBFUSCATION_PATTERNS_RE if p.search(raw_body))
            if count >= 3:
                severity = "HIGH" if _reconstructs_to_action(body) else "MEDIUM"
                add("R082", "Shell Obfuscation Density", severity, "obfuscation",
                    f"{enclosing[i]}() line has {count} obfuscation indicators: {body.strip()[:80]}",
                    position=enclosing[i], count=count, body=body.strip()[:80])
                break
