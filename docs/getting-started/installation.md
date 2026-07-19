# Installation

TrustSight requires **Python 3.12 or later** and **git** (for cloning AUR repositories during analysis).

---

## pip (recommended)

```bash
pip install trustsight
```

This installs the tool and its core dependencies: `pygit2`, `tldextract`, `rich`, and `openai`.

## AUR (dogfooding)

Arch users can install the `trustsight` AUR package via their preferred helper:

```bash
yay -S trustsight
# or
paru -S trustsight
```

## From source

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight
pip install -e .
```

The editable install (`-e`) lets you pull and test new versions immediately.

---

## LLM setup (optional)

TrustSight scores every package **without** an LLM. The scoring pipeline is fully deterministic : the LLM never calculates, modifies, or influences a score. It only translates the existing score and breakdown into a plain-English sentence. See [how the trust model works](../explanation/trust-model.md) for a deeper explanation.

If you want English verdicts instead of template strings, set an API key:

```bash
# Environment variable (recommended : never checked into repos)
export TRUSTSIGHT_API_KEY=sk-...

# Or stored in config
trustsight config set api_key sk-...
```

The provider defaults to `openai` (compatible with OpenAI, NVIDIA, Together, and any OpenAI-compatible endpoint). To change the model or provider:

```bash
trustsight config set base_url https://integrate.api.nvidia.com/v1
```

If no API key is configured, template verdicts are used. The tool works identically in either mode : only the prose changes.

---

## Verify the installation

```bash
trustsight --help
```

You should see a list of available commands: `review`, `inspect`, `history`, `config`.

Check your configuration:

```bash
trustsight config show
```

---

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| LLM verdict reads as a template ("Version bump. No structural changes.") | No API key set | Set `TRUSTSIGHT_API_KEY` or run `trustsight config set api_key` |
| `trustsight review` prints "No outdated packages found." | No AUR packages installed, or all are up to date | Install an AUR package or wait for updates |
| `ModuleNotFoundError: No module named 'pygit2'` | System git not found or libgit2 headers missing | Install `libgit2-dev` (Debian) / `libgit2` (Arch), then reinstall |
