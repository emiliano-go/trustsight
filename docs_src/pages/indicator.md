<!-- description: Indicator rules: a declared surface matches signed external data - the shipped IOC list or a federated publisher's set. Outside the heuristic score, alerted at maximum priority. -->

# Indicators


An indicator rule asks one question: does a declared surface match an entry in
**signed external data**? The mechanism is membership, not a heuristic - the
answer is exact equality against a list TrustSight did not invent. H056 reads
the shipped `iocs.toml` and any locally imported baseline; the IOC federation
stage reads a publisher's signed indicator set. They are the same mechanism, so
H056 is filed here and keeps its id; new federation matches will take `I` ids.

Indicator matches are **outside the heuristic score** and never add points. A
`confirmed` match is FATAL; the rest map to a severity by the indicator's
confidence tier. See [IOC Federation](../reference/ioc.md) for the transport and the
update cadence.

See [Rule Mechanics](mechanics.md) for the field table, the severity
weights and the reserved identifier ranges.

---
