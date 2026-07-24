# Security

## Vulnerability disclosure policy

TrustSight takes the security of its analysis pipeline seriously. If you believe you have found a vulnerability in TrustSight itself (not in a package it audits), please report it via email.

**Contact:** emiliano.gandini@protonmail.com  
**PGP key fingerprint:** `F759D6D49B0A395AB922414A5CC3B4C50D37E793`

### Disclosure process

1. Report the vulnerability via email. Include as much detail as possible: steps to reproduce, affected versions, and potential impact.
2. You will receive an acknowledgement within 72 hours.
3. A fix will be developed and released within 90 days of the initial report.
4. Do not file a public issue or disclose the vulnerability before a patch is available.

### Scope

**In scope:**
- Scoring bypass: crafting a PKGBUILD diff that produces a lower score than the risk warrants
- LLM prompt injection that changes the verdict despite verdict-integrity assertions
- Rule evasion: bypassing R001-R013 or C001-C003 detection patterns
- Cache poisoning: manipulating the SQLite novelty database to suppress signals

**Out of scope:**
- Compromised upstream AUR packages: TrustSight audits them; that is the point
- Runtime behavioral analysis is not yet implemented

## Security-relevant defaults

- **FATAL rules always fire.** R012 (prompt injection) and R013 (unicode bidi) have FATAL severity and hard-stop the score at 100 regardless of other signals. They cannot be disabled through configuration.
- **LLM is optional.** The LLM only translates the deterministic score breakdown into English; it never calculates scores. If the LLM is unavailable, misconfigured, or produces a verdict that fails integrity assertions, the fallback verdict is used.
- **Verdict assertions gate output.** Every LLM-generated verdict is checked against the deterministic score before display. Assertions verify length, score disclosure, FATAL-signal presence, and low-score hyperbole.
