<!-- description: Rules for a name being claimed, or a dependency set changing, in a way that redirects what actually gets installed. -->

# Naming and Dependencies


A name is claimed, or a dependency set changes, in a way that redirects
what gets installed. H029 covers the package's own name impersonating a
popular one; D002 covers the same attack against a dependency name; H064
and D004 cover `provides`/`replaces` claiming a name that belongs to
something else.

Most rules here need the dependency corpus, which is seeded from every
`depends`/`makedepends`/`optdepends`/`checkdepends` entry in the AUR plus every
package name and `provides` alias. Without the seed they stay silent rather
than treating an empty table as "nothing has ever been seen". The exceptions
read other sources: D003 uses the static `[patterns] network_tools` list, and
H053 and H059 compare the name against host and repository data. Aggregate
expansion is counted rather than named, so it lives in
[count-based](count-based.md#h030-rule).

Dependency arrays are read in both assignment forms: a bare `depends=(...)`
and a compound `depends+=(...)`, including arch-suffixed spellings such as
`depends_x86_64+=(...)`. Appended names reach every D-rule and the dependency
change summary, so `+=` is not an evasion. D001/D002 need the corpus and the
main calibration gates run cold: the `warm` fixture group is scanned twice by
`gate_d_series_warm` - once with the committed dependency corpus, where the
labels must pass, and once cold, where D001/D002 must stay silent. The
D-series fire rates below are point-in-time measurements against the seeded
corpus.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
