<!-- description: The documentation contribution policy: who a page is for, what question it answers, which existing page owns the subject, and where the page is linked from. -->

# Documentation Policy

TrustSight's documentation is organized by **audience and question**, not by
file age. One concept has one authoritative source; other pages link to it
instead of restating it. This policy keeps the structure from drifting back
into parallel indexes.

## Before adding a page

Answer these five questions in the pull request:

1. **Who is the intended reader?** A new user, an operator, a security
   researcher, a developer or a maintainer.
2. **What question does the page answer?** State it in one sentence.
3. **Does an existing page already cover this subject?** Search the docs and
   the generated catalog first. If the answer belongs on an existing page,
   extend it rather than create a parallel one.
4. **What kind of page is it?** Tutorial (teach), guide (accomplish a task),
   explanation (why), or reference (exact facts and contracts).
5. **Where is it linked from?** A page with no contextual inbound link is an
   orphan, even if search can find it.

A new page does **not** automatically become a navigation entry. The global
navigation carries the primary audience journeys; advanced pages are linked
from their section landing page and from the pages that need them.

## Where content belongs

| Content | Canonical location |
|---|---|
| What a user should do | `start-here/` or `workflows/` |
| Why the system works this way | `security-design/` and `explanation/` |
| What a rule claims and how it is defined | `rules/` (one page per category) |
| Exact parameters, fields and contracts | `reference/` |
| How to develop, evaluate and release | `contributing/` |
| What a finding does and does not establish | `rules/interpretation.md` |

If two pages explain the same concept, merge them; do not keep both and add a
"see also". If a page grows past its subject, split it by responsibility and
link the parts.

## Generated content

Do not edit these by hand:

- the category legend in `docs/rules/index.md`;
- the catalog in `docs/rules/definitions.md`;
- the per-category rule index and definitions;
- the compatibility anchors in `docs/reference/rules/system.md`.

Edit `docs_src/sections/`, `docs_src/pages/`, `docs_src/nature/` or
`docs_src/layout.json`, then run:

```bash
uv run python scripts/build_rules_index.py
```

`tests/test_generated_docs.py` fails if the committed pages disagree with
their sources.

## Required checks

A documentation change is not done until:

- every internal link resolves;
- every page has a title and a `description` comment;
- every navigation entry points at an existing file;
- every rule ID is on the page its category owns;
- generated pages match their sources; and
- the site builds with `zensical build`.

Run the focused suite with:

```bash
uv run --extra dev pytest tests/test_docs.py tests/test_generated_docs.py
```

## Removing or moving a page

Move content before deleting a file. Then:

- update every relative link, navigation entry and anchor;
- keep a compatibility page or an anchor stub when a published URL would
  otherwise break, particularly for rule IDs and security clauses;
- check the changelog and the README for references; and
- verify the docs build before removing the old file.

Never delete a page only because its title looks redundant. Delete it when
its content has a canonical home and every reference points there.

## Security documentation is different

A change to a security guarantee, a `B` clause, an `A` invariant or an
enforcement gate is a **security-documentation change**. It needs the same
review as the code it describes, and the guarantee and its gate must change
together. Editorial cleanup must not weaken or soften a claim.
