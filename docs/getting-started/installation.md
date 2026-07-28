# Installation

TrustSight requires **Python 3.10 or later** and **git** (for cloning AUR repositories during analysis).

---

## Install

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si
```

!!! note "Not published to the AUR yet"

    `aur.archlinux.org/trustsight.git` does not exist. Build from the PKGBUILD in this repository, as above.

The PKGBUILD runs the full test suite during build, and `makepkg -si` pulls in the dependencies (`pygit2`, `tldextract`, `rich`, `openai`, `typer`) as proper system packages. The result is tracked by `pacman`, so it upgrades and uninstalls like anything else on the system.

Do not install with `pip`: it is blocked by the system Python's `externally-managed-environment` protection, and forcing it with `--break-system-packages` risks conflicting with `pacman`-managed files.

For a development checkout with the test dependencies, use a virtualenv instead (see [development setup](../contributing/development-setup.md)).

---

## LLM setup (optional)

TrustSight scores every package **without** an LLM. The scoring pipeline is fully deterministic : the LLM never calculates, modifies, or influences a score. It only translates the existing score and breakdown into a plain-English sentence. See [how the trust model works](../explanation/trust-model.md) for a deeper explanation.

If you want English verdicts instead of template strings, run the interactive setup wizard:

```bash
trustsight config setup
```

It walks you through provider choice (OpenAI-compatible or Ollama), endpoint URL, API key, and model selection, then optionally tests the connection.

### Quick manual setup

For scripting or environment variables:

```bash
# Environment variable (recommended : never checked into repos)
export TRUSTSIGHT_API_KEY=sk-...

# Or stored in config
trustsight config set api_key sk-...
```

The provider defaults to `openai` (compatible with OpenAI, NVIDIA, Together, and any OpenAI-compatible endpoint). To change the endpoint or model:

```bash
trustsight config set base_url https://integrate.api.nvidia.com/v1
trustsight config set model meta/llama-3.1-8b-instruct
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
| `ModuleNotFoundError: No module named 'pygit2'` | System git not found or libgit2 headers missing | `sudo pacman -S libgit2`, then reinstall |
