<!-- description: Where the maintainer-and-metadata rules come from (a change of custody) and what a finding means. -->

# Maintainer and Metadata

Mechanics live on the

<!-- generated: nature-rules -->
**Rules in this nature:** [C006](../rules/maintainer-and-metadata.md#c006), [C030](../rules/maintainer-and-metadata.md#c030), [H026](../rules/maintainer-and-metadata.md#h026), [H037](../rules/maintainer-and-metadata.md#h037), [H044](../rules/maintainer-and-metadata.md#h044), [H049](../rules/maintainer-and-metadata.md#h049), [H050](../rules/maintainer-and-metadata.md#h050), [H051](../rules/maintainer-and-metadata.md#h051), [H054](../rules/maintainer-and-metadata.md#h054), [H058](../rules/maintainer-and-metadata.md#h058), [H063](../rules/maintainer-and-metadata.md#h063), [H074](../rules/maintainer-and-metadata.md#h074), [H086](../rules/maintainer-and-metadata.md#h086), [H088](../rules/maintainer-and-metadata.md#h088), [H105](../rules/maintainer-and-metadata.md#h105) (15 rules).
<!-- /generated: nature-rules -->
[Maintainer and Metadata system page](../rules/maintainer-and-metadata.md).

## Where it comes from

Think of a **deed to a house, and the signature on it**. You do not need to
see the new owner do anything suspicious; the moment the handwriting on the
deed changes, you look at everything else with fresh eyes. Most PKGBUILD
attacks are delivered through an *account*, not a clever parser: a new
maintainer, a fresh key, a `pkgver` that lies, a commit that touches the
metadata and nothing else. The T-series reads the human and recipe metadata
around the code, because a change of custody usually shows there first.

The rules look at the maintainer key's age and reputation, unusual `pkgver`
and `pkgrel` moves, checksum work that rewrites history, and metadata that
contradicts the recipe. None of this is proof; the value is that a metadata
anomaly makes the *code* diff worth a second read, which is exactly the
situation a silent maintainer swap creates.

## What a finding means

- The finding is about a signal on the account or the metadata, dated and
  attributed, not an accusation about the package's contents.
- A new maintainer plus a code change in the same window is the pattern;
  either alone is routine.
- These rules feed the blast-radius and novelty scoring, so they often move a
  run's band without being dramatic on their own.

## See also

- [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)
- [Maintainer and Metadata system page](../rules/maintainer-and-metadata.md)
