import tomllib
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "trustsight"
DATA_DIR = Path.home() / ".local" / "share" / "trustsight"
CACHE_DIR = Path.home() / ".cache" / "trustsight" / "repos"

DEFAULT_CONFIG = """\
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0

[source_bucket_weights]
trusted_forge = -10
official = 0
self_hosted = 10
raw_hosting = 15
unknown = 20
homograph_attack = 30

[novelty_weights]
url_first_in_package = 10
url_first_globally = 15
maintainer_first_in_package = 20

[llm]
provider = "openai"
model = "gpt-4o-mini"
enabled = true
max_tokens = 1024
temperature = 0.3
top_p = 1
seed = 42

[llm.openai]
api_key = ""
base_url = "https://api.openai.com/v1"

[llm.ollama]
url = "http://localhost:11434/v1"

[deep]
enabled = false
threshold = 80

[diff]
max_context_lines = 3
max_diff_chars_for_llm = 2000

[limits]
default_review_limit = 20

[verification_evidence]
checksum_present = -10
validpgpkeys_declared = -10
gpg_verify_present = -5

[pinning_weights]
checksum_pinned = -5
tag_pinned = -3
branch_pinned = 0
unpinned = 0
"""

DEFAULT_RULES = """\
[[rules]]
id = "R001"
name = "Remote Script Execution"
pattern = 'curl.*\\|\\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\\s+sh|source\\s+/dev/stdin)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R002"
name = "Wget Pipe to Shell"
pattern = 'wget.*\\|\\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\\s+sh|source\\s+/dev/stdin)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R003"
name = "Base64 Decode and Execute"
pattern = 'base64.*(?:\\-d|\\-\\-decode).*\\|'
severity = "CRITICAL"
category = "obfuscation"
match_target = "resolved"

[[rules]]
id = "R006"
name = "Insecure Download Protocol"
pattern = 'https?://.*\\.tar\\.gz.*\\|'
severity = "MEDIUM"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R007"
name = "Install File Modification"
pattern = '\\+.*\\.install.*'
severity = "MEDIUM"
category = "installer"
match_target = "raw_line"

[[rules]]
id = "R008"
name = "Unexpected File Download"
pattern = '\\b(python|ruby|perl)\\s+-c\\s+https?://'
severity = "HIGH"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R009"
name = "Privilege Escalation"
pattern = '\\bsudo\\b'
severity = "CRITICAL"
category = "privilege"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R010"
name = "Uses curl in PKGBUILD"
pattern = '\\bcurl\\s'
severity = "LOW"
category = "network_usage"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R011"
name = "Uses wget in PKGBUILD"
pattern = '\\bwget\\s'
severity = "LOW"
category = "network_usage"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R012"
name = "LLM Prompt Injection"
pattern = 'ignore\\s+(?:all\\s+)?previous\\s+(?:instructions|commands|input)'
severity = "FATAL"
category = "injection"
match_target = "resolved"

[[rules]]
id = "R013"
name = "Unicode Bidi Override"
pattern = '[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200D\\uFEFF]'
severity = "FATAL"
category = "unicode"
match_target = "raw_line"
"""

DEFAULT_DOMAINS = """\
[trusted_forges]
domains = ["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"]

[official_projects]
domains = [
    "downloads.apache.org",
    "nginx.org",
    "python.org",
    "ftp.gnu.org",
    "kernel.org",
    "dl.google.com",
    "get.videolan.org",
    "download.qt.io",
    "nodejs.org",
    "rubygems.org",
    "pypi.org",
    "crates.io",
    "registry.npmjs.org",
    "archive.archlinux.org",
    "static.rust-lang.org",
]

[raw_hosting]
domains = [
    "raw.githubusercontent.com",
    "pastebin.com",
    "gist.github.com",
    "paste.ee",
    "0x0.st",
    "termbin.com",
]
"""


def ensure_dirs():
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_default_file(path: Path, content: str):
    if not path.exists():
        path.write_text(content)


def ensure_default_configs():
    ensure_dirs()
    write_default_file(CONFIG_DIR / "config.toml", DEFAULT_CONFIG)
    write_default_file(CONFIG_DIR / "rules.toml", DEFAULT_RULES)
    write_default_file(CONFIG_DIR / "trusted_domains.toml", DEFAULT_DOMAINS)


def load_toml(name: str) -> dict:
    path = CONFIG_DIR / name
    if not path.exists():
        ensure_default_configs()
    with open(path, "rb") as f:
        return tomllib.load(f)


def _toml_value(val: str) -> str:
    if val.lower() in ("true", "false"):
        return val.lower()
    try:
        int(val)
        return val
    except ValueError:
        pass
    escaped = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def set_config(key: str, value: str):
    path = CONFIG_DIR / "config.toml"
    if not path.exists():
        ensure_default_configs()
    text = path.read_text()
    section_path = key.rsplit(".", 1)
    section = section_path[0] if len(section_path) > 1 else ""
    key_name = section_path[-1] if len(section_path) > 1 else key

    if section:
        header = f"[{section}]"
        if header in text:
            new_text = []
            in_section = False
            replaced = False
            for line in text.splitlines(keepends=True):
                stripped = line.strip()
                if stripped == header:
                    in_section = True
                    new_text.append(line)
                    continue
                if in_section:
                    if stripped.startswith("["):
                        in_section = False
                        if not replaced:
                            new_text.append(f'{key_name} = {_toml_value(value)}\n')
                            replaced = True
                        new_text.append(line)
                        continue
                    if stripped.startswith(f"{key_name} ") or stripped.startswith(f"{key_name}="):
                        new_text.append(f'{key_name} = {_toml_value(value)}\n')
                        replaced = True
                        continue
                    new_text.append(line)
                    continue
                new_text.append(line)
            if not replaced:
                new_text.append(f'{key_name} = {_toml_value(value)}\n')
            text = "".join(new_text)
        else:
            text += f"\n{header}\n{key_name} = {_toml_value(value)}\n"
    else:
        import re
        pattern = re.compile(rf"^{re.escape(key_name)}\s*=\s*.*", re.MULTILINE)
        if pattern.search(text):
            text = pattern.sub(f'{key_name} = {_toml_value(value)}', text)
        else:
            text += f'\n{key_name} = {_toml_value(value)}\n'

    path.write_text(text)


def load_config() -> dict:
    return load_toml("config.toml")


def load_rules() -> list[dict]:
    data = load_toml("rules.toml")
    return data.get("rules", [])


def load_domains() -> dict:
    return load_toml("trusted_domains.toml")
