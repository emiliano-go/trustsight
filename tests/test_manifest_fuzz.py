"""Property-based fuzz tests for the hostile manifest boundary.

Not a replacement for Atheris coverage-guided fuzzing, but it runs in the
normal suite and exercises the same contract: a hostile document returns a
value or a named refusal, never a hang or an uncaught exception.
"""

from __future__ import annotations

import time

from hypothesis import HealthCheck, given, settings, strategies as st

from trustsight.analysis.manifest_syntax import (
    ManifestSyntaxError,
    load_ini,
    load_json,
    load_toml,
    load_xml,
    load_yaml,
)
from trustsight.analysis.manifests import parse_manifest

YAML_TOKENS = st.sampled_from([
    "a: 1\n", "a: &x {b: *x}\n", "<<: [*a, *a]\n", "[]", "{}", "- x\n",
    "!!python/object:os.system\n", "\t", " ", "\n", "\"", "'", "#", ": ",
    "&a", "*a", "|", ">", "[", "]", "{", "}",
])
MANIFEST_PATHS = st.sampled_from([
    "environment.yml", "pubspec.yaml", "pnpm-lock.yaml", "package.json",
    "Cargo.toml", "pom.xml", "setup.cfg", "requirements.txt",
])


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=4096))
def test_yaml_load_is_bounded_or_refused(text):
    start = time.monotonic()
    try:
        load_yaml(text)
    except ManifestSyntaxError:
        pass
    assert time.monotonic() - start < 2.0


@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(YAML_TOKENS, max_size=120).map("".join))
def test_yaml_token_soup_terminates(text):
    start = time.monotonic()
    try:
        load_yaml(text)
    except ManifestSyntaxError:
        pass
    assert time.monotonic() - start < 2.0


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(MANIFEST_PATHS, st.text(max_size=2048))
def test_manifest_parse_never_raises(path, text):
    start = time.monotonic()
    doc = parse_manifest(path, text)
    if doc is not None:
        assert isinstance(doc.unresolved, tuple)
    assert time.monotonic() - start < 3.0


@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=2048))
def test_other_loaders_refuse_or_return(text):
    for loader in (load_json, load_toml, load_xml, load_ini):
        try:
            loader(text)
        except (ManifestSyntaxError, ValueError):
            pass
