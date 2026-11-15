<!-- description: Rules targeting the reviewer rather than the shell: reviewer-directed template text and codepoints that make displayed text differ from executed text. -->

# Deception and Anti-Analysis


These rules target the reviewer, not the shell. R012 and R013 are the two
FATAL rules: reviewer-directed template text, and codepoints that make displayed
text differ from executed text. Both contribute weight 0 and name themselves in
the verdict label (`Low (FATAL: R012)`). Neither
establishes an author's intent: R012 is a high-severity template tripwire for
reviewer manipulation, while R013 identifies a concrete display/execution
deception mechanism. When neither fires, nothing has been established.

H067 and the reserved H012/H013 are the inverse direction: the recipe
checking whether it is being watched. A build script that probes for a
debugger, a VM or a CI runner has no legitimate reason to care.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
