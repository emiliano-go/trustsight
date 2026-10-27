<!-- description: Where the naming-and-dependency rules come from (counterfeit names and transitive trust) and what a finding means. -->

# Naming and Dependencies

Mechanics live on the

<!-- generated: nature-rules -->
**Rules in this nature:** [D001](../rules/naming-and-dependency.md#d001), [D002](../rules/naming-and-dependency.md#d002), [D003](../rules/naming-and-dependency.md#d003), [D004](../rules/naming-and-dependency.md#d004), [D005](../rules/naming-and-dependency.md#d005), [H006](../rules/naming-and-dependency.md#h006), [H029](../rules/naming-and-dependency.md#h029-rule), [H048](../rules/naming-and-dependency.md#h048), [H053](../rules/naming-and-dependency.md#h053), [H059](../rules/naming-and-dependency.md#h059), [H064](../rules/naming-and-dependency.md#h064), [H104](../rules/naming-and-dependency.md#h104), [H106](../rules/naming-and-dependency.md#h106) (13 rules).
<!-- /generated: nature-rules -->
[Naming and Dependencies system page](../rules/naming-and-dependency.md).

## Where it comes from

Two ideas, both older than code.

The first is the **counterfeit storefront**: a shop opens next door to a
trusted one, under a name one letter off, and waits for customers to walk in
by mistake. That is typosquatting - a package name that is a near-miss of a
far more popular one (or the same name under the wrong base), relying on the
reader's eye rather than on any code. G005, the impersonation campaign rule,
is the collective form: one account publishing many such clones.

The second is **transitive trust**, the "friend of a friend" that gets in on
someone else's word. Adding a dependency is how you get *someone else's*
install hook and code into a user's system. A new dependency that is not a
real upstream, or a version pin that redirects to an unowned repo, smuggles in
code the package itself never wrote - the class the ecosystem calls dependency
confusion.

## What a finding means

- Name findings are about the relationship between this name and a famous
  one; the finding carries both, so the reviewer sees the target being
  imitated.
- A single odd name is weak; a burst from one maintainer is G005.
- Dependency findings are about trust transitivity: the reviewer approved
  *this* package, not the transitive one the recipe just added.

## See also

- [Correlation](correlation.md); the G005 campaign form
- [Naming and Dependencies system page](../rules/naming-and-dependency.md)
