<!-- description: Where the install-and-persistence rules come from (code that revives after the build) and what a finding means. -->

# Install and Persistence

Mechanics live on the [Install and Persistence system page](../rules/install-and-persist.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [C017](../rules/install-and-persist.md#c017), [C029](../rules/install-and-persist.md#c029), [C031](../rules/install-and-persist.md#c031), [C032](../rules/install-and-persist.md#c032), [H017](../rules/install-and-persist.md#h017), [H023](../rules/install-and-persist.md#h023), [H032](../rules/install-and-persist.md#h032), [H035](../rules/install-and-persist.md#h035), [H039](../rules/install-and-persist.md#h039), [H062](../rules/install-and-persist.md#h062), [H084](../rules/install-and-persist.md#h084), [H089](../rules/install-and-persist.md#h089), [H093](../rules/install-and-persist.md#h093), [H095](../rules/install-and-persist.md#h095), [H100](../rules/install-and-persist.md#h100), [H108](../rules/install-and-persist.md#h108), [R007](../rules/install-and-persist.md#r007), [R017](../rules/install-and-persist.md#r017), [R052](../rules/install-and-persist.md#r052), [R053](../rules/install-and-persist.md#r053), [R054](../rules/install-and-persist.md#r054), [R059](../rules/install-and-persist.md#r059), [R144](../rules/install-and-persist.md#r144) (23 rules).
<!-- /generated: nature-rules -->

## Where it comes from

This is the **sleeper agent**: the intruder does not act while the guards are
watching, but leaves something behind that wakes on its own trigger, long
after everyone has stopped looking. A build that only runs at build time is
contained by the sandbox that ran it. Persistence is how code survives past
that: writing a `systemd` unit, a cron job, a shell profile hook, or a
`pacman` hook that re-runs later, so the execution happens *after* the
reviewer has moved on and the container is gone.

It is the difference between a guest who leaves at the end of the evening and
one who quietly copies a key so they can come back. The rules cover the
standard Linux persistence surfaces a package has no business installing
silently: units and timers, cron and anacron, shell rc files, pacman hooks,
and udev rules. Together they answer "does this package arrange to run again
on its own?".

## What a finding means

- The finding is about the **mechanism**, not the motive: a service unit is
  not inherently malicious, but it is a durable execution path and it must be
  visible on the diff.
- Where the write lands matters more than the write itself: `/etc/...` and
  per-user autostart directories persist; a file inside the build tree does
  not.
- A chain that installs a unit *and* installs a fetch-and-execute script is
  the compound case worth escalating; read the two findings together.

## See also

- [Structural User Rules](../../explanation/structural-user-rules.md); how
  package structure is read
- [Install and Persistence system page](../rules/install-and-persist.md)
