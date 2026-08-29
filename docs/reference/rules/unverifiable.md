<!-- description: W-series findings report what the analysis could not check, at weight 0 and always shown. A claim about the analysis, not about the recipe. -->

# Unverifiable

W rules report **what the analysis could not check**.

Every other rule says "this recipe does something". A W finding says "this
analysis could not verify something", attached to the line it applies to. It
is the same statement as a [coverage gap](../report-schema.md), moved from
the run to the line.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

## Reading a W finding

- It never changes the score, the risk band, or the flagged decision.
- It is always shown, unlike other weight-0 findings, because a statement
  whose only value is to a reader is worthless if filtered.
- It is not evidence of wrongdoing and must not be reported as such.

## Why W rules carry no weight

The behaviour they describe is what packaging is. A recipe that unpacks a
declared, checksummed archive and runs something from inside it is following
the format. The checksum proves the bytes arrived unaltered; it says nothing
about what they do.

Pricing that would put a finding on a large share of the ecosystem and make
the number mean less, which is what [B10](../../security.md) prevents: a gap
must not add points. Silence is the other option, and silence is what the
boundary documentation had to describe as something TrustSight cannot see.

A W finding tells a reader something specific: *this* line runs *that* file,
and nobody - not the checksum, not this tool - has read it.

## Where the scored counterpart lives

Some W surfaces have a subset narrow enough to score. Those are separate
rules, because a W is weight-0 by construction:

| W rule | Scored counterpart |
|---|---|
| [W001](#w001) executes unread code | [H094](fetch-and-execution.md#h094), the same act during `package()` |
| [W004](#w004) unread manifest | [X020](crossfire.md#x020), the recipe writing one |
| [W006](#w006) unread generated config | [X022](crossfire.md#x022), the same config handed to a tool |

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [W001](#w001) | Executes Code This Analysis Did Not Read | INFO |
| [W002](#w002) | Build Resolves Dependencies From A Registry | INFO |
| [W003](#w003) | Applies A Patch This Analysis Did Not Read | INFO |
| [W004](#w004) | Build Engine Runs A Manifest This Analysis Did Not Read | INFO |
| [W005](#w005) | Build Runs A Target Whose Recipe Was Not Read | INFO |
| [W006](#w006) | Generated File Names A Build-Only Path | INFO |
<!-- /generated: page-index -->

### W001: Executes Code This Analysis Did Not Read {#w001}

**INFO** (weight 0) · category `unverifiable`

Fires when a build function runs a script - through an interpreter, or as
`./name` - whose path is neither declared in `source=()` nor committed to the
repository.

| Fires | Quiet |
|---|---|
| `bash "$srcdir/scripts/postunpack.sh"` | `bash setup.sh` when `setup.sh` is declared |
| `./install.sh` | `./configure --prefix=/usr` |
| `python3 "$srcdir/x-1.0/gen.py"` | `python3 setup.py build` |
| `chroot "$srcdir/root" /bin/sh /x.sh` | `/bin/sh /usr/share/p/helper.sh` |
| `xterm -e "bash $PWD/x.sh"` | `make` |

[H083](fetch-and-execution.md#h083) claims the case where the executed file
is a declared source, and H081 where it is committed. What is left is code
that runs and that nobody looked at.

Two shapes qualify and no third: an interpreter naming a file, and a `./`
invocation. A bare path-shaped word at a command position is not one - that
reading matched the MIME type in `x-scheme-handler/orcaslicer` and the
`usr/bin/env` of a shebang line.

The standard entry points of an unpacked tree are excluded: `configure`,
`setup.py`, `Makefile.PL`, `autogen.sh`, `gradlew`.

A sandbox wrapper establishes a new root, so an absolute path after `chroot`
or `systemd-nspawn` is tree content rather than a system file.

Fires on 0.09% of the benign corpus.

### W002: Build Resolves Dependencies From A Registry {#w002}

**INFO** (weight 0) · category `unverifiable`

Fires on a build step that resolves packages from a language registry:
`npm install`, `pip install -r`, `cargo fetch`, `go mod download` and
siblings.

The recipe names a *set* of packages and a registry decides which bytes
satisfy it, at build time, after review. No checksum in the recipe covers
them, and the resolved versions are not in the analysed text.

The run already says this once, as the `unpinned_build_deps` coverage gap.
What a gap cannot say is *where*.

Fires on 0.31% of the benign corpus.

### W003: Applies A Patch This Analysis Did Not Read {#w003}

**INFO** (weight 0) · category `unverifiable`

Fires on `patch` or `git apply` naming a `.patch`/`.diff` that is not
committed to the repository.

A patch edits the source before it is built, and the edit is whatever the
patch says. A committed patch is one [H090](fetch-and-execution.md#h090)
reads; a declared remote one sits behind a checksum this tool never
downloads.

A tarball is upstream's own code. A patch is a change to it that the packager
chose, which makes it more interesting to a reader, not less.

Fires on 2.06% of the benign corpus - the highest rate in the series, and the
correct answer rather than a tuning problem.

### W004: Build Engine Runs A Manifest This Analysis Did Not Read {#w004}

**INFO** (weight 0) · category `unverifiable`

Fires when `make`, `ninja`, `bazel`, `scons` or a sibling is given an
explicit manifest argument that is neither declared nor committed.

| Fires | Quiet |
|---|---|
| `ninja -f "$srcdir/gen.ninja"` | `ninja -C build` |
| `make -f "$srcdir/build.mk" all` | `make -f setup.mk` when declared (H083) |

Anchored on an explicit `-f`/`--file`. A bare `make` also runs a manifest
nobody read, and that is most of the ecosystem; reporting it would say
nothing. Naming a particular file is a choice.

Zero occurrences in the benign corpus.

### W005: Build Runs A Target Whose Recipe Was Not Read {#w005}

**INFO** (weight 0) · category `unverifiable`

Fires when `make` or `ninja` is given a non-standard target and no `Makefile`
is committed.

| Fires | Quiet |
|---|---|
| `make all dist-hooks` | `make install` |
| `make stage1` | `make -j$(nproc) all` |
| | `make DESTDIR="$pkgdir" install` |

`make install` is a contract every build system honours. `make dist-hooks`
names a recipe that exists only in this project's Makefile, and that Makefile
arrived inside a tarball this analysis never opened.

Flags and variable assignments are not targets.

Fires on 0.28% of the benign corpus.

### W006: Generated File Names A Build-Only Path {#w006}

**INFO** (weight 0) · category `unverifiable`

Fires when a `printf`/`echo`/`cat`/`tee` writes a file outside `$pkgdir`
whose content names `$srcdir`, `$startdir`, `$PWD` or `$BUILDDIR` in a field
that is not merely descriptive.

[X022](crossfire.md#x022) claims this when the recipe goes on to hand the
file to a tool. Without that second line there is no evidence anything reads
it: the file may be a build input, a generated `.pc`, a note.

Two exclusions: `>&2` is a file descriptor rather than a file, and
`cat "$srcdir/a" | tee b` copies a file, where the build path names what to
read rather than content the recipe authored.

The descriptive test reads the **written text**, not the shell line, because
`printf "Comment=built in $srcdir" > f` starts with `printf`.

Zero occurrences in the benign corpus.
