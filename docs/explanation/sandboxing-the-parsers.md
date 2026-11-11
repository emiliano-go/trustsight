<!-- description: Why committed manifests are parsed in a separate Linux sandbox, what that sandbox removes, and what it does not protect. -->

# Sandboxing the Parser Stack

The tokenizer was the first hostile parser isolated because expansion has an
amplification property. The committed dependency manifests have a different
problem: they are parsed by third-party code that this project consumes but
does not audit. A YAML, XML or TOML parser defect is not a detection issue;
it is a defect in the machine running the review.

## What moved

`yaml`, `xml.etree.ElementTree`, `tomllib`, `configparser`, `json`/JSONC and
the manifest format extractors now run in `sandbox/manifest_worker.py`, a
read-role worker launched by `sandbox/manifest_client.py`. The parent sends
`(path, text)` over the framed protocol and receives a serialised
`ManifestDoc`; it never calls the loaders on package-controlled bytes.

The worker is already a Linux sandbox before the first request:

- unprivileged user namespace, private network namespace;
- Landlock filesystem rules (ABI 6 required), no writable path;
- seccomp allowlist with no socket or `execve`/`fork`;
- `RLIMIT_AS`/`RLIMIT_CPU`, `PR_SET_NO_NEW_PRIVS`, no capabilities.

A worker that cannot apply that floor refuses to serve. The client turns a
dead, timed-out or over-cap worker into a named refusal; the manifest layer
records a coverage gap, never a clean result. The client also stops a worker
that times out or replies with an invalid frame, bounds the parse cache by
bytes, refuses a snapshot above the framed-request cap, and resets inherited
worker state after ``fork``.

The worker also owns the analysis tokenizer and the AUR snapshot archive.
`trustsight.tokenizer` sends engine operations to the same content worker, so
the analysis path has no second tokenizer child and no nested sandbox to
spawn. `full_aur/fetch.py` downloads the snapshot, then sends the bytes to
the worker; `analysis/archive_snapshot.py` walks the tar and applies the
member/total bounds there. The parent never opens the archive. The worker
uses the tokenizer **engine** in-process; `sandbox/tokenizer_ops.py` is the
shared dispatch table, imported by the content worker and by the standalone
`expand_worker` used only by the tokenizer sandbox tests.

## Why not just `safe_load`

`yaml.safe_load` is still the loader, but safe loading does not bound
resources. PyYAML 6.0.3 is the latest release and does not contain the
merge-key fan-out fix; that fix is carried in
`analysis/manifest_syntax.py` as a bounded `SafeLoader` subclass, with
explicit node, alias, depth, merge-entry and duplicate-key limits. The
manifest worker is the second layer: even a parser defect spends the worker,
not the analysis process, its database handle or its filesystem.

## What it does not protect

The kernel, the Python interpreter and the parser libraries remain trusted.
The sandbox contains a defect; it does not prove the parser correct. The
worker can still be killed by its own resource limits, which is reported as
a refusal rather than a quiet analysis. The TOML/INI/JSON parsers are pure
Python; the C surfaces in this path are expat (XML) and the JSON accelerator,
and the whole path is below the same trusted-dependency boundary as the rest
of the tool.
