"""The false-positive issue intake parses the form, not free prose."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import fp_intake  # noqa: E402


BODY = """### What kind of report is this?

Bad rule trigger (malicious false positive)

### TrustSight version

trustsight 0.22.0

### AUR package

demo

### Feed alert URL

https://watcher.trustsight.org/2026-10-23/120000/

### Rule id

R007

### What TrustSight reported

```json
{"findings": [{"rule_id": "R007"}]}
```

### Why this is a bad rule trigger

The path is a committed systemd user unit, not persistence.

### PKGBUILD or diff

```diff
+install -Dm644 demo.service "$pkgdir/usr/lib/systemd/user/demo.service"
```

### Command or mode

trustsight inspect demo

### Config fingerprint

abc
"""


def test_a_complete_form_has_no_missing_fields_and_a_slug():
    fields = fp_intake.parse_body(BODY)

    assert fp_intake._missing(fields) == []
    assert fp_intake._slug(fields) == "2026-10-23/120000"
    assert fields["kind"].startswith("Bad rule trigger")


def test_a_missing_why_and_diff_are_named():
    body = BODY.replace(
        "The path is a committed systemd user unit, not persistence.", ""
    ).replace(
        '```diff\n+install -Dm644 demo.service '
        '"$pkgdir/usr/lib/systemd/user/demo.service"\n```',
        "",
    )
    fields = fp_intake.parse_body(body)

    assert "why" in fp_intake._missing(fields)
    assert "pkgbuild" in fp_intake._missing(fields)


def test_the_comment_names_the_missing_evidence():
    fields = fp_intake.parse_body(BODY)
    comment = fp_intake._comment(fields, [], "2026-10-23/120000")

    assert fp_intake.MARKER in comment
    assert "required evidence is present" in comment
    assert "2026-10-23/120000" in comment


def test_no_response_is_treated_as_missing():
    body = BODY.replace("R007", "_No response_")
    fields = fp_intake.parse_body(body)

    assert "rule_id" in fp_intake._missing(fields)
