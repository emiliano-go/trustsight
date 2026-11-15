<!-- description: Rules that fire on how a diff is written rather than on what it does: tokenizer defeat, command reconstruction, and the techniques used to hide a payload. -->

# Crossfire


Crossfire rules fire on **how a diff is written**, not on what it does.

Every other rule family matches a payload: a fetch, a write, a privilege
change. Crossfire matches the technique used to hide one. A word the
tokenizer cannot reduce to a literal, a command carried in a config value, a
pipeline whose sink has no name the analyser knows - each is evidence on its
own, whatever payload sits behind it.

This is a reference page. For how rules are weighted and scoped, see
[Rule Mechanics](mechanics.md). For the families that match payloads, start at
[All Rules](index.md).

## Why the family exists

Payload rules depend on resolution. When resolution fails, they produce
silence, and silence reads identically to a clean package. Crossfire inverts
that: a defeated tokenizer produces a finding rather than nothing, so evasion
and alarm are the same event.

One crossfire rule covers the evasion surface of every payload rule at once.
It does not identify which payload was hidden, only that hiding occurred.

## What crossfire does not do

- It does not replace tokenizer fixes. A payload hidden by an unanticipated
  technique still passes.
- It does not claim bytes another rule claims. Base64-to-shell belongs to
  [R003](obfuscation.md#r003) and [R043](obfuscation.md#r043), bidi and
  homoglyph codepoints to [R013](deception.md#r013), and `~/` writes to
  [H032](install-and-persist.md#h032).

## The gate is the file, not the function {#the-gate-is-the-file-not-the-function}

Crossfire rules run against shell files. A `.desktop` entry, a licence text
or a README is not a shell file, and a character or construct that would be
evasion in a recipe is ordinary content there.

A heredoc body that is only printed (`cat <<'MSG' ... MSG` around advisory
text) is output, not executed shell, so the crossfire command rules skip it.
[X020](#x020) still reads the body, because the manifest is what a later
engine runs.

---
