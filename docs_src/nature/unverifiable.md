<!-- description: Where the unverifiable rules come from (an honest map of its own blind spots) and what a finding means. -->

# Unverifiable

Mechanics live on the [Unverifiable category page](unverifiable.md).

## Where it comes from

The old maps wrote **"here be dragons"** at the edge of the known world rather
than leaving the margin blank. A blank margin claims there is nothing there; a
dragon warns the traveller where knowledge stops. Some recipes do something
TrustSight cannot confirm is safe *or* unsafe, and the honest response is to
say so rather than stay silent. A source fetched from a URL not in the
known-upstream set, a build step whose effect depends on a remote service, a
binary blob with no corresponding source: the tool marks these as unverifiable
and hands the judgement to the reviewer.

This category exists because silence reads as "checked and fine". Its whole
purpose is to prevent a gap in coverage from masquerading as a clean result.

## What a finding means

- The finding marks something outside the verifiable scope, with the reason.
  It is not a claim of danger; it is a refusal to pretend to have checked.
- These findings are surfaced even when the score is low, because they change
  how much weight the *rest* of the report deserves.
- Treat an unverifiable finding as a question directed at the reviewer, not
  an answer from the tool.

## See also

- [What TrustSight Cannot See](../explanation/limitations-and-uncertainty.md)
- [Unverifiable category page](unverifiable.md)
