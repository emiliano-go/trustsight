<!-- description: Where the count-based rules come from (volume as signal, not a single event) and what a finding means. -->

# Count-Based

Mechanics live on the [Count-Based category page](count-based.md).

## Where it comes from

One swallow does not make a summer, but a **swarm of them** means the season
has turned. Some signals are not a pattern but a *rate*: how many network
calls, how many new dependencies, how many distinct hosts, how many decode
steps. One is normal, a dozen is a different animal. The count-based family
watches those magnitudes and flags the recipe that crosses a learned
threshold, without claiming any single occurrence was wrong.

The single mosquito is not the problem; the swarm is. These rules trade
precision for reach: a kitchen-sink build can trip them benignly, so their
thresholds are set from the benign corpus's actual distribution rather than
from intuition.

## What a finding means

- The finding reports the count and the threshold, so the reviewer can judge
  whether the volume is explained by the package's purpose.
- These are context rules: read alongside the concrete findings they magnify,
  not as standalone accusations.
- Because traffic and dependency counts drift with ecosystem fashion, their
  thresholds are the ones most likely to be retuned; treat a persistent
  benign count finding as a calibration note.

## See also

- [Corpus and Priors](../explanation/historical-and-behavioral-analysis.md)
- [Fire Rates](../reports/fire-rates.md)
- [Count-Based category page](count-based.md)
