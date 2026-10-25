<!-- uid: TS-0086 -->
<!-- anchor: h030-rule -->
<!-- name: Dependency-Set Expansion -->

- **Condition:** A single diff adds 3+ `depends`/`makedepends`/`optdepends`/`checkdepends` entries whose **count × mean rarity** exceeds the expansion gate (≥1.5, tuned on corpus).

**Why not count alone:** Adding 5 deps that are all common (`glibc`, `qt6-base`, `cmake`) is a normal heavy build and should not fire. The signal is count **weighted by how rare/novel each added dep is**, reusing D001's `dependency_observation_count` as a rarity proxy. Novel/obscure deps push the magnitude up; common deps contribute near zero.

**No double-count with D001:** H030 fires on the **aggregate pattern** (multiple rare deps appearing together), which is a materially different signal from any single dep being novel. Individual D001 per-dep firings remain untouched. This is not the H027 mistake: the aggregate condition captures a different phenomenon (co-occurrence, not individual presence).

**Origin:** Socket/Snyk dependency-surface profiling - a version bump that expands the dependency graph with obscure entries is the "expand attack surface quietly" shape. D001 already flags each novel dep individually; H030 catches the disproportionate co-occurrence.
