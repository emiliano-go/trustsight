# Security Policy

TrustSight audits AUR PKGBUILD updates, so its own integrity matters. Reports
are welcome and taken seriously.

## Reporting a vulnerability

**Contact:** `emiliano.gandini@protonmail.com` — PGP `F759D6D49B0A395AB922414A5CC3B4C50D37E793`

Do **not** open a public issue before a patch exists. Provide steps to
reproduce, the affected version (`trustsight --version`), and what an attacker
gains; a PKGBUILD or diff that demonstrates the issue is better than a
description. Acknowledgement within 72 hours, triage within 7 days. Only the
latest release is supported; fixes ship in a new version, with no backports.

What counts as a vulnerability — and what is a rule request instead — is
defined in [Part D: Vulnerability reporting](https://docs.trustsight.org/security/vulnerability-reporting/).
In short: a defect is a case where the tool moved between taxonomy rows
silently, or failed to protect the machine while doing it. "It missed
something" is usually a rule request, not a vulnerability.

## Verifying a release

Release artifacts are covered by a detached GPG signature made with the
commit-signing key above, and the AUR PKGBUILD pins that key in
`validpgpkeys`. Verify with:

```bash
gpg --recv-keys F759D6D49B0A395AB922414A5CC3B4C50D37E793
gpg --verify trustsight-<version>.tar.gz.sig trustsight-<version>.tar.gz
```

See [Release signing](https://docs.trustsight.org/security/release-signing/) for
the full model.
