<!-- description: Where the deception rules come from (sleight of hand against the reviewer) and what a finding means. -->

# Deception and Anti-Analysis

Mechanics live on the [Deception category page](deception.md).

## Where it comes from

This is **sleight of hand**. A magician does not change the world, only what
the audience sees; a deceiving recipe does not change what the shell runs,
only what the reviewer reads. The family is the class of tricks aimed at the
audience rather than at the compiler: homoglyphs and lookalike characters,
right-to-left overrides that reorder displayed text, invisible or zero-width
bytes, and control characters that render differently than they parse.

A homoglyph here is the equivalent of a **counterfeit note**: it passes a
glance, and fails only when someone bothers to compare it character by
character against the real thing. These attacks do nothing at build time.
Their whole purpose is to make what the reviewer *sees* differ from what the
shell *runs*, which is why they are read as anti-analysis evidence rather than
as build behaviour.

## What a finding means

- The finding is high-confidence by construction: Unicode confusables,
  bidi overrides, and zero-width characters appearing in a build recipe have
  essentially no benign reading, so these rules can weigh heavily.
- The matched text is shown escaped so the reviewer sees the concealed
  character, not a lookalike that hides it.
- Treat a deception finding as an explanation for *other* findings being hard
  to see; it often rides alongside an obfuscated payload.

## See also

- [Why Static Analysis](../explanation/static-analysis-and-resolution.md); how the
  tokenizer sees what the terminal hides
- [Deception category page](deception.md)
