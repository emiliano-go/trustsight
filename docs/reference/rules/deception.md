<!-- description: Rules targeting the reviewer rather than the shell: reviewer-directed template text and codepoints that make displayed text differ from executed text. -->

# Deception and Anti-Analysis

These rules target the reviewer, not the shell. R012 and R013 are the two
FATAL rules: reviewer-directed template text, and codepoints that make displayed
text differ from executed text. Both hard-stop the score at 100. Neither
establishes an author's intent: R012 is a high-severity template tripwire for
reviewer manipulation, while R013 identifies a concrete display/execution
deception mechanism. When neither fires, nothing has been established.

H067 and the reserved H012/H013 are the inverse direction: the recipe
checking whether it is being watched. A build script that probes for a
debugger, a VM or a CI runner has no legitimate reason to care.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H012](#h012) | Strace detection attempt (TracerPid check) | CRITICAL |
| [H013](#h013) | Strace log truncated (possible flood evasion) | HIGH |
| [H067](#h067) | Anti-Analysis Check | HIGH |
| [R012](#r012) | Prompt Injection Detection | FATAL |
| [R013](#r013) | Unicode Bidi Override | FATAL |
<!-- /generated: page-index -->

### R012: Prompt Injection Detection {#r012}

- **Target:** `resolved`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `injection`
- **Pattern:** `\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+)*(?:previous|above|prior|earlier|preceding|foregoing|existing)\b|^[^\S\n]*(?:#[^\S\n]*)?(?:system|assistant)[^\S\n]*:[^\S\n]*\S|</?(?:system|instructions?|admin|prompt|assistant)\s*>|\byou\s+are\s+(?:an?|the)\s+[^.\n]{0,48}?(?:model|assistant|ai\b)|\bnew\s+instructions?\s*:|\bdo(?:\s+not|n['’]t)\s+(?:flag|warn|analy[sz]e|review|scan)\b|\bdo(?:\s+not|n['’]t)\s+report\s+(?:any\s+|the\s+)?(?:security|issues?|concerns?|problems?|findings?|warnings?|anything)\b|\b(?:mark|classify|report|treat|label|approve)\b[^.\n]{0,24}?\bas\s+(?:safe|benign|clean|harmless|trusted|ok)\b|\b(?:claude|chatgpt|gpt-?[0-9]?|copilot|gemini|llm|ai\s+assistant)\b[^.\n]{0,60}?\b(?:ignore|approve|skip|overlook|flag)\b`
- **Comments:** scanned (`include_comments`)
- **Description:** Detects template-shaped text addressed to whoever *reads* the PKGBUILD rather than to the shell that runs it: instruction overrides ("ignore the previous instructions"), role markers (`system:`, `assistant:`), tag-like injections (`<system>`, `<instructions>`), personas ("you are a helpful model..."), suppression orders ("do not flag/warn/analyze") and pre-declared verdicts ("mark this as safe"). Comment lines are scanned, unlike every rule that describes what the shell executes, because this is reviewer-facing text. Calibrated at 22/22 labelled injection fixtures with 0 fires across the historical 3,739-diff benign corpus. This is a **reviewer-directed template tripwire**, not proof of an author's intent or a general prompt-injection detector: a match requires reviewer scrutiny, and a non-match establishes nothing. Score hard-stops at 100 regardless of other signals.

### R013: Unicode Bidi Override {#r013}

- **Target:** `raw_line`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `unicode`
- **Pattern:** `[\u202A-\u202E\u2066-\u2069\u2060-\u2064\U000E0000-\U000E007F]|(?<![^\x00-\x7F])[\u200B-\u200F\uFEFF](?![^\x00-\x7F])`
- **Description:** Detects directionality overrides, isolates, invisible operators, tag characters, and zero-width joiners placed between ASCII neighbours. These codepoints can make displayed text differ from executed text. The ASCII-neighbour restriction preserves attacks hidden inside ASCII commands or URLs while dropping legitimate use in localized `GenericName[...]` lines.

The rule splits deceptive codepoints into two classes, because they are not equally suspicious.

**Fires unconditionally**: bidi overrides and isolates (U+202A-U+202E, U+2066-U+2069), invisible operators (U+2060-U+2064), and tag characters (U+E0000-U+E007F). None has a legitimate use in a build recipe. These are the characters that make displayed text differ from executed text.

**Fires only between ASCII neighbours**: zero-width and directional characters (U+200B-U+200F, U+FEFF). U+200B-U+200D are *mandatory* joiners in Malayalam, Lao, Devanagari and other scripts: a localized `GenericName[ml]=` line in a browser package legitimately contains U+200D. Because R013 is FATAL, firing on one scored an entirely benign package 100/100. Two packages in the benign corpus (`brave-origin-bin`, `zen-browser-bin`) did exactly this. Requiring ASCII on both sides preserves the attack (a joiner hidden inside an ASCII command or URL, such as `https://evil.com<U+200D>/pkg.tar.gz`) while dropping the false positive.

- **Note:** Score hard-stops at 100 regardless of other signals. The previous pattern omitted U+200E/U+200F, U+2060-U+2064 and the tag block, which is where the documented recall gap came from; `unicode.py` already listed them.

### H012: Strace detection attempt (TracerPid check) {#h012}

- **Target:** `runtime` (resolved execution path)
- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Pattern:** `(?!)` (never matches)
- **Description:** Reading `/proc/self/status` `TracerPid` to detect a debugger or sandbox. Anti-analysis behaviour. Reserved `never-match` runtime placeholder.

### H013: Strace log truncated (possible flood evasion) {#h013}

- **Target:** `runtime` (resolved execution path)
- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Pattern:** `(?!)` (never matches)
- **Description:** A beacon/timestamp flood that forces an audit log to truncate. Reserved `never-match` runtime placeholder; complements the H012 debugger probe.

### H067: Anti-Analysis Check {#h067}

- **Severity:** HIGH (weight 25)
- **Category:** `anti_analysis`
- **Condition:** A build or install function probes for a debugger (`TracerPid`), a VM (`systemd-detect-virt`, DMI or hypervisor strings), a sandbox, or CI (`$CI`, `$GITHUB_ACTIONS`, `$CONTAINER`, `/.dockerenv`), from `[patterns] anti_analysis_probes`.

A build script checking whether it is being watched has no legitimate purpose.
Architecture and feature detection (`uname -m`, `getconf`) is not a probe and
does not fire.

Fire rate: 0 of 3246.
