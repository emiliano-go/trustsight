<!-- description: Rules claiming that something was fetched, something was executed, or a path connects the two. The densest group in the ruleset. -->

# Fetch and Execution


Code reaches the machine and runs. Every rule here claims one of three
things: something was fetched, something was executed, or a path connects
the two. They are the densest group in the ruleset because the shapes are
many and the claim is the same one, so a rule that only covers `curl |
bash` leaves the rest of the family open.

The pipe-to-shell rules (R001, R002) are the canonical form. H075, H082 and
H083 exist because the pipe is not required: process substitution, a
download split across two lines, and a declared `source=()` script all put
fetched code in a shell without one. H077 moves the same question to parse
time, where the fetch happens before any build step or checksum applies.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
