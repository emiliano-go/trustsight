<!-- description: Where the temporal rules come from (timing as forensic evidence and the ecosystem's memory) and what a finding means. -->

# Temporal Context

Mechanics live on the [Temporal Context category page](temporal.md).

## Where it comes from

The idea comes from **forensics**: an alibi is checked against the clock, and
a timeline puts events in an order that a single photograph cannot. Some
attacks are only visible in time. A commit made at 03:00, a burst of
publications inside one minute, a change reverted and reapplied, an update
that lands days after the maintainer went quiet: none of these is anomalous on
its own line, but the *when* is data a single-snapshot review throws away.

There is an immune reading here too. The adaptive immune system protects you
because it *remembers* what it has already met. Temporal rules are TrustSight's
memory: the same observation store that lets the alerting layer recognise a
returning infection is what lets a single run notice that this package is
behaving unlike its own past.

The rules compare the current run against a baseline in the observation store,
so they need history to say anything. On a cold store they stay quiet by
construction rather than guessing.

## What a finding means

- The finding compares this run to what came before: a change of behaviour,
  a burst, a near-simultaneous edit to many packages.
- Temporal findings are contextual and weak in isolation; they matter as
  corroboration for a code change that already looked odd.
- An empty history is not a clean bill of health. It means the temporal rules
  cannot see yet, which the run reports as reduced coverage.

## See also

- [Cold Start and Maturity](../explanation/scoring-and-verdicts.md)
- [Corpus and Priors](../explanation/historical-and-behavioral-analysis.md)
- [Temporal Context category page](temporal.md)
