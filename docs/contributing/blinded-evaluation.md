<!-- description: How to submit an independent evaluation of TrustSight's detection and false-positive rates, and why the committed fixtures cannot supply one. -->

# Blinded Evaluation

TrustSight's committed fixtures and locked corpus are internal regression
materials. They are useful for preventing known behavior from drifting, but
they are not an independent estimate of detection or false-positive rates.
This process accepts externally held, blinded material for an evaluation whose
labels are not available to the people tuning the rules.

## Intake

Open a private security report using the repository's reporting channel and
title it `Blinded evaluation intake`. Do not include live credentials,
malware binaries, private package contents, or identifying data in a public
issue.

Provide:

- A contact and disclosure constraints.
- The evaluation question, target population, and sampling method.
- The number of benign and malicious examples, label definitions, and the
  time period they represent.
- Whether examples are real, redacted, synthetic, or reconstructed.
- A cryptographic digest of the sealed evaluation bundle.
- The exact TrustSight version and configuration to evaluate, or permission to
  evaluate the current released version with its shipped configuration.

Maintainers first confirm that the material is safe and lawful to handle, that
the proposed labels answer the stated question, and that the evaluator retains
the labels. Acceptance does not imply that TrustSight can safely execute,
download, or retain submitted content.

## Blinded Process

1. The evaluator supplies de-identified diffs and metadata sufficient for the
   chosen analysis mode, without outcome labels or label-revealing filenames.
2. Maintainers record the bundle digest, tool version, configuration fingerprint,
   corpus/seed state, command line, and any exclusions before running it.
3. Maintainers run the released tool without adding rules, changing thresholds,
   or inspecting labels. Coverage gaps, failures, and unsupported input are
   retained as outcomes rather than silently removed.
4. The evaluator unseals labels after the predictions and run record are fixed.
   Results report the full confusion matrix, exclusions, coverage gaps, and
   confidence intervals where the sample supports them.
5. Any rule tuning prompted by the result occurs only after the evaluation is
   closed. A new evaluation requires a new sealed bundle; the same set is not
   reused as evidence for the tuned version.

## Publication

Publish the methodology, bundle digest, tool and configuration versions,
population limits, exclusions, and aggregate results when disclosure permits.
Do not describe the result as a general recall or false-positive rate beyond
the evaluated population. If the material cannot be shared, publish as much of
the protocol and aggregate outcome as the evaluator permits, and state the
resulting reproducibility limitation.
