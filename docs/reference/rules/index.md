<!-- description: The complete TrustSight rule catalog by category, with severity, weight, match target and scope for every R, H, C, D, S, X, W and P identifier. -->

# Rules Reference

TrustSight uses rules to detect structural signals in PKGBUILD diffs. The
inventory is the R-series regex rules, the H-series heuristics, sabotage rules S001-S008, crossfire
rules X001-X023, integrity-change rules C001-C009, dependency rules
D001-D004, declared-practice rules P001-P008, and unverifiable rules
W001-W006.

Each rule contributes according to its severity weight, match target and
scope, except the P and W series, which are weight 0 and report rather than
score.

This page is the map. [The rule system reference](system.md) explains how
the engine works and holds everything that is not an individual rule: the
`rules.toml` field table, the severity weights, the FATAL short-circuit,
the measured fire rates, the series taxonomy, and the reserved identifier
ranges. Each rule's own definition lives on the page for its category.

## Categories {#categories}

A rule's **category** is the kind of claim it makes. There is exactly one
per rule and the set is closed, so every rule has exactly one page. This is
not the same axis as the per-rule `category` field in `rules.toml`, which
names the *capability* a match touched (`network`, `persistence`,
`obfuscation`) and is what H027 counts when it looks for capability
density. A rule can be `category = "meta"` and still be a composition rule.

The taxonomy is defined in `src/trustsight/categories.py` as
`RuleCategory`, and `tests/test_docs.py` fails the build if a rule's
documentation drifts to the wrong page. The two tables on this page are
generated from it by `scripts/build_rules_index.py`.

| Category | Slug | Rules | What a rule here claims |
|----------|------|-------|-------------------------|
<!-- generated: legend -->
| [Fetch and Execution](fetch-and-execution.md) | `fetch-and-execution` | 36 | Code reaches the machine and runs: a fetch, an execution, or the path between the two. |
| [Obfuscation](obfuscation.md) | `obfuscation` | 8 | The recipe hides what it does from a reader by encoding, indirection, or runtime assembly. |
| [Deception and Anti-Analysis](deception.md) | `deception` | 5 | The recipe targets whoever reviews it rather than the shell that runs it, or checks whether it is being watched. |
| [Install and Persistence](install-and-persist.md) | `install-and-persist` | 17 | Something survives the build: a root-time hook, a unit, a privileged bit, a file in the user's profile. |
| [Staging and Reconnaissance](staging-and-recon.md) | `staging-and-recon` | 8 | The build steps outside its staging roots, hides a drop, or profiles the host it is running on. |
| [Integrity and Verification](integrity.md) | `integrity` | 26 | A verification the recipe used to carry is weakened, removed, or cannot cover what it claims to. |
| [Naming and Dependencies](naming-and-dependency.md) | `naming-and-dependency` | 10 | A name is claimed or a dependency set changes in a way that redirects what gets installed. |
| [Maintainer and Metadata](maintainer-and-metadata.md) | `maintainer-and-metadata` | 13 | Who owns the package, or a long-stable declared property, changed. |
| [Temporal Context](temporal.md) | `temporal` | 3 | How recently the package or this revision appeared, independent of any diff content. |
| [Composition](composition.md) | `composition` | 2 | Distinct kinds of finding co-occurred; the combination is the signal, and the points are already scored elsewhere. |
| [Count-Based](count-based.md) | `count-based` | 5 | A count of indicators crossed a fixed threshold within one artifact or one cluster. |
| [Corpus Behavioral](corpus-behavioral.md) | `corpus-behavioral` | 7 | The package's position in, or deviation from, the corpus baseline - silent without prior observations. |
| [Crossfire](crossfire.md) | `crossfire` | 23 | The evasion technique itself, not the payload it hides: a rule here fires on how a thing was written rather than on what it does. |
| [Sabotage](sabotage.md) | `sabotage` | 8 | A payload aimed at the operator's machine rather than at getting something out of it: resource exhaustion, deletion, permission sabotage, service disruption, resource theft. |
| [Unverifiable](unverifiable.md) | `unverifiable` | 6 | Not a claim about the recipe but about the analysis: something the package will run that this run could not read. Weight 0 always, and always shown. |
<!-- /generated: legend -->

Crossfire is the anti-evasion family introduced in the current ruleset. Its
23 rules detect tokenizer defeat and command reconstruction; see
[crossfire.md](crossfire.md) for the family boundary and rule descriptions.

## Reading a rule entry

Each entry states the same facts in the same order:

- **Target**: `resolved` (post-variable-expansion command strings),
  `raw_line` (the literal diff line), or `programmatic` (emitted from code
  in `analysis/`, because the condition needs more than one line).
- **Severity**: `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO`,
  with the weight it contributes. See
  [severity weights](system.md#severity-weights).
- **Category**: the capability field described above, not the page.
- **Pattern** or **Condition**: what makes the rule fire. Quoted patterns
  are checked against the shipped `rules.toml` on every test run, so a
  pattern here cannot drift from the one that runs.
- **Fire rate**, where measured: hits on the current 3,739-diff benign corpus, unless a page explicitly identifies a historical measurement.
  These are false-positive rates. The full table is in
  [measured fire rates](system.md#experimental-fire-rates).

## Quick reference {#quick-reference}

Every documented rule, with the page that defines it. The identifier space
is deliberately non-contiguous; see
[reserved identifiers](system.md#not-rules).

| Id | Name | Severity | Category |
|----|------|----------|----------|
<!-- generated: catalog -->
| [C001](integrity.md#c001) | Checksum Changed Without Source Change With Stable Version | HIGH | [Integrity and Verification](integrity.md) |
| [C002](integrity.md#c002) | Checksum Updated With Version Bump | INFO | [Integrity and Verification](integrity.md) |
| [C003](integrity.md#c003) | Source URL Changed Without Version Bump | INFO | [Integrity and Verification](integrity.md) |
| [C004](integrity.md#c004) | Checksum Removed For Unchanged Source | CRITICAL | [Integrity and Verification](integrity.md) |
| [C005](integrity.md#c005) | Binary Artifact From Untrusted Source | MEDIUM | [Integrity and Verification](integrity.md) |
| [C006](maintainer-and-metadata.md#c006) | Maintainer Change With New Source Domain | HIGH | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [C007](fetch-and-execution.md#c007) | Command Substitution In Source Array | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [C008](integrity.md#c008) | Unread Content Moved Under A Stable Version | HIGH | [Integrity and Verification](integrity.md) |
| [C009](integrity.md#c009) | Unread Content Moved With The Version | INFO | [Integrity and Verification](integrity.md) |
| [D001](naming-and-dependency.md#d001) | Novel Dependency Added | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [D002](naming-and-dependency.md#d002) | Typosquatted Dependency | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [D003](naming-and-dependency.md#d003) | New Network-Using Makedepends | MEDIUM | [Naming and Dependencies](naming-and-dependency.md) |
| [D004](naming-and-dependency.md#d004) | Dependency Hijack Via Provides | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [H001](integrity.md#h001) | Checksum Disabled | HIGH | [Integrity and Verification](integrity.md) |
| [H002](integrity.md#h002) | Checksum Emptied | HIGH | [Integrity and Verification](integrity.md) |
| [H003](fetch-and-execution.md#h003) | Insecure Download Protocol | LOW | [Fetch and Execution](fetch-and-execution.md) |
| [H004](fetch-and-execution.md#h004) | Privilege Escalation | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [H005](integrity.md#h005) | validpgpkeys Added | MEDIUM | [Integrity and Verification](integrity.md) |
| [H006](naming-and-dependency.md#h006) | New Make/Opt/Check Dependency | INFO | [Naming and Dependencies](naming-and-dependency.md) |
| [H007](staging-and-recon.md#h007) | Symlink Redirect | MEDIUM | [Staging and Reconnaissance](staging-and-recon.md) |
| [H008](integrity.md#h008) | Suspicious Environment Variable | MEDIUM | [Integrity and Verification](integrity.md) |
| [H009](fetch-and-execution.md#h009) | Network connection attempt | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [H010](staging-and-recon.md#h010) | Suspicious file write | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [H011](fetch-and-execution.md#h011) | Sensitive binary execution | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H012](deception.md#h012) | Strace detection attempt (TracerPid check) | CRITICAL | [Deception and Anti-Analysis](deception.md) |
| [H013](deception.md#h013) | Strace log truncated (possible flood evasion) | HIGH | [Deception and Anti-Analysis](deception.md) |
| [H014](obfuscation.md#h014) | Eval or Exec Usage | MEDIUM | [Obfuscation](obfuscation.md) |
| [H015](fetch-and-execution.md#h015) | Critical Build Function Modified | INFO | [Fetch and Execution](fetch-and-execution.md) |
| [H016](fetch-and-execution.md#h016) | Hidden Network Fetch In Build | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H017](install-and-persist.md#h017) | Install Hook Fetches Or Executes | HIGH | [Install and Persistence](install-and-persist.md) |
| [H018](integrity.md#h018) | Patch Applied From Outside The Build Tree | HIGH | [Integrity and Verification](integrity.md) |
| [H019](integrity.md#h019) | Source URL Downgraded To HTTP | MEDIUM | [Integrity and Verification](integrity.md) |
| [H020](temporal.md#h020) | Very Recent Update | INFO | [Temporal Context](temporal.md) |
| [H021](temporal.md#h021) | Brand New Package | INFO | [Temporal Context](temporal.md) |
| [H022](temporal.md#h022) | Stale Package Revived | MEDIUM | [Temporal Context](temporal.md) |
| [H023](install-and-persist.md#h023) | Install Hook Present | INFO | [Install and Persistence](install-and-persist.md) |
| [H024](integrity.md#h024) | GPG Verification Removed | HIGH | [Integrity and Verification](integrity.md) |
| [H025](integrity.md#h025) | Build Environment Subversion | HIGH | [Integrity and Verification](integrity.md) |
| [H026](maintainer-and-metadata.md#h026) | Untrusted Maintainer Takeover | HIGH | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H026](maintainer-and-metadata.md#h026-corpus) | Untrusted Maintainer Takeover (corpus path) | HIGH | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H027](composition.md#h027) | Capability Density Anomaly | INFO | [Composition](composition.md) |
| [H028](corpus-behavioral.md#h028) | Accelerated Release Cadence | - | [Corpus Behavioral](corpus-behavioral.md) |
| [H029](naming-and-dependency.md#h029-rule) | Package-Name Typosquat | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [H030](count-based.md#h030-rule) | Dependency-Set Expansion | MEDIUM | [Count-Based](count-based.md) |
| [H031](fetch-and-execution.md#h031) | Version-In-URL Injection | MEDIUM | [Fetch and Execution](fetch-and-execution.md) |
| [H032](install-and-persist.md#h032) | Write To User Home Or RC | HIGH | [Install and Persistence](install-and-persist.md) |
| [H033](integrity.md#h033) | Moved Git Ref | HIGH | [Integrity and Verification](integrity.md) |
| [H034](fetch-and-execution.md#h034) | Exotic Source Protocol | MEDIUM | [Fetch and Execution](fetch-and-execution.md) |
| [H035](install-and-persist.md#h035) | Foreign Package Manager In Install Hook | HIGH | [Install and Persistence](install-and-persist.md) |
| [H036](count-based.md#h036) | Shell Obfuscation Density | MEDIUM | [Count-Based](count-based.md) |
| [H037](maintainer-and-metadata.md#h037) | Long-Stable Property Changed | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H038](staging-and-recon.md#h038) | World-Writable Staging | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [H039](install-and-persist.md#h039) | Systemd ExecStart From Runtime-Writable Path | HIGH | [Install and Persistence](install-and-persist.md) |
| [H040](staging-and-recon.md#h040) | Host Reconnaissance | INFO | [Staging and Reconnaissance](staging-and-recon.md) |
| [H041](fetch-and-execution.md#h041) | Upload To Paste Or File-Drop Host | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H042](staging-and-recon.md#h042) | Hidden Drop | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [H043](composition.md#h043) | Attack-Chain Composition | INFO | [Composition](composition.md) |
| [H044](maintainer-and-metadata.md#h044) | Ownership Transition | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H045](count-based.md#h045) | Mass Adoption | HIGH | [Count-Based](count-based.md) |
| [H046](corpus-behavioral.md#h046) | Orphan/Adoption Dependency | MEDIUM | [Corpus Behavioral](corpus-behavioral.md) |
| [H047](integrity.md#h047) | Security-Relevant Build Flag Change | HIGH | [Integrity and Verification](integrity.md) |
| [H048](naming-and-dependency.md#h048) | Dependency Vendored Into Source | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [H049](maintainer-and-metadata.md#h049) | Source Host Changed | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H050](maintainer-and-metadata.md#h050) | Version Scheme Changed | INFO | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H051](maintainer-and-metadata.md#h051) | Package Description Changed | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H052](count-based.md#h052) | Shared Source Repository | HIGH | [Count-Based](count-based.md) |
| [H053](naming-and-dependency.md#h053) | Name/Host Consensus Divergence | MEDIUM | [Naming and Dependencies](naming-and-dependency.md) |
| [H054](maintainer-and-metadata.md#h054) | Build System Changed | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H055](count-based.md#h055) | Attribute Burst | MEDIUM | [Count-Based](count-based.md) |
| [H056](corpus-behavioral.md#h056) | Known Indicator of Compromise | FATAL | [Corpus Behavioral](corpus-behavioral.md) |
| [H057](corpus-behavioral.md#h057) | Transitive Exposure | INFO | [Corpus Behavioral](corpus-behavioral.md) |
| [H058](maintainer-and-metadata.md#h058) | Maintainer Baseline Deviation | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H059](naming-and-dependency.md#h059) | Name/Repo Divergence | MEDIUM | [Naming and Dependencies](naming-and-dependency.md) |
| [H060](corpus-behavioral.md#h060) | Transitive Orphan Exposure | INFO | [Corpus Behavioral](corpus-behavioral.md) |
| [H061](corpus-behavioral.md#h061) | Dependency Centrality | INFO | [Corpus Behavioral](corpus-behavioral.md) |
| [H062](install-and-persist.md#h062) | Pacman Hook Installed | MEDIUM | [Install and Persistence](install-and-persist.md) |
| [H063](maintainer-and-metadata.md#h063) | Epoch Introduced | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H064](naming-and-dependency.md#h064) | Provides/Replaces Scope Expansion | HIGH | [Naming and Dependencies](naming-and-dependency.md) |
| [H065](obfuscation.md#h065) | Obfuscated Literal Reconstructed | INFO | [Obfuscation](obfuscation.md) |
| [H066](integrity.md#h066) | Embedded Binary In Tree | HIGH | [Integrity and Verification](integrity.md) |
| [H067](deception.md#h067) | Anti-Analysis Check | HIGH | [Deception and Anti-Analysis](deception.md) |
| [H068](fetch-and-execution.md#h068) | Reconstructed Executable Payload | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H069](fetch-and-execution.md#h069) | Build-time Generation Then Execution | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H070](integrity.md#h070) | Archive Trailer Anomaly | HIGH | [Integrity and Verification](integrity.md) |
| [H071](fetch-and-execution.md#h071) | Covert Egress | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H072](fetch-and-execution.md#h072) | Write Then Execute | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H073](corpus-behavioral.md#h073) | Introduction Rate Deviation | MEDIUM | [Corpus Behavioral](corpus-behavioral.md) |
| [H074](maintainer-and-metadata.md#h074) | Adopt-then-Modify | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H075](fetch-and-execution.md#h075) | Indirect Remote Execution | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [H076](staging-and-recon.md#h076) | Build Writes Outside Staging Root | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [H077](fetch-and-execution.md#h077) | Parse-time Network Fetch | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H078](integrity.md#h078) | Signing Key Set Changed | HIGH | [Integrity and Verification](integrity.md) |
| [H079](integrity.md#h079) | Build Flags Weakened | HIGH | [Integrity and Verification](integrity.md) |
| [H080](obfuscation.md#h080) | Indirect Command Expansion | CRITICAL | [Obfuscation](obfuscation.md) |
| [H081](fetch-and-execution.md#h081) | Committed File Executed Without Declaration | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H082](fetch-and-execution.md#h082) | Fetch Then Execute | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [H083](fetch-and-execution.md#h083) | Downloaded Source File Executed | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H084](install-and-persist.md#h084) | Service ExecStart Targets Undeclared Binary | HIGH | [Install and Persistence](install-and-persist.md) |
| [H085](staging-and-recon.md#h085) | PATH Injection With Undeclared Directory | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [H086](maintainer-and-metadata.md#h086) | Adopted From Orphan | MEDIUM | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H087](integrity.md#h087) | Recipe Changed Without Upstream | MEDIUM | [Integrity and Verification](integrity.md) |
| [H088](maintainer-and-metadata.md#h088) | Adopted, Recipe Rewritten, Unpinned Fetch | HIGH | [Maintainer and Metadata](maintainer-and-metadata.md) |
| [H089](install-and-persist.md#h089) | Packaged File Names A Build-Only Path | HIGH | [Install and Persistence](install-and-persist.md) |
| [H090](fetch-and-execution.md#h090) | Committed Companion Carries A Fetch-Execute Payload | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [H091](integrity.md#h091) | Checksum Array Shorter Than Source Array | HIGH | [Integrity and Verification](integrity.md) |
| [H092](integrity.md#h092) | Metadata Names A Source The Recipe Does Not | HIGH | [Integrity and Verification](integrity.md) |
| [H093](install-and-persist.md#h093) | Committed Config Points At A Build-Only Path | HIGH | [Install and Persistence](install-and-persist.md) |
| [H094](fetch-and-execution.md#h094) | Unread Script Executed During Packaging | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [H095](install-and-persist.md#h095) | Boot Or Image Artifact Built From The Source Tree | HIGH | [Install and Persistence](install-and-persist.md) |
| [R001](fetch-and-execution.md#r001) | Remote Script Execution | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [R002](fetch-and-execution.md#r002) | Wget Pipe to Shell | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [R003](obfuscation.md#r003) | Base64 Decode and Execute | CRITICAL | [Obfuscation](obfuscation.md) |
| [R007](install-and-persist.md#r007) | Install File Modification | MEDIUM | [Install and Persistence](install-and-persist.md) |
| [R008](fetch-and-execution.md#r008) | Unexpected File Download | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [R010](fetch-and-execution.md#r010) | Uses curl in PKGBUILD | LOW | [Fetch and Execution](fetch-and-execution.md) |
| [R011](fetch-and-execution.md#r011) | Uses wget in PKGBUILD | LOW | [Fetch and Execution](fetch-and-execution.md) |
| [R012](deception.md#r012) | Prompt Injection Detection | FATAL | [Deception and Anti-Analysis](deception.md) |
| [R013](deception.md#r013) | Unicode Bidi Override | FATAL | [Deception and Anti-Analysis](deception.md) |
| [R017](install-and-persist.md#r017) | Setuid/Setgid Permission | HIGH | [Install and Persistence](install-and-persist.md) |
| [R039](obfuscation.md#r039) | Eval With Dynamic Content | CRITICAL | [Obfuscation](obfuscation.md) |
| [R040](obfuscation.md#r040) | Shell -c With Dynamic Payload | CRITICAL | [Obfuscation](obfuscation.md) |
| [R041](fetch-and-execution.md#r041) | Shell Network Redirection | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [R042](fetch-and-execution.md#r042) | Download Then Execute | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [R043](obfuscation.md#r043) | Base64 Blob Decode | CRITICAL | [Obfuscation](obfuscation.md) |
| [R044](fetch-and-execution.md#r044) | Interpreter One-Liner With Network | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [R045](obfuscation.md#r045) | Binary Encoding Pipe | MEDIUM | [Obfuscation](obfuscation.md) |
| [R046](fetch-and-execution.md#r046) | Source URL Uses IP Address | MEDIUM | [Fetch and Execution](fetch-and-execution.md) |
| [R047](fetch-and-execution.md#r047) | Source URL Uses Non-Standard Port | LOW | [Fetch and Execution](fetch-and-execution.md) |
| [R048](fetch-and-execution.md#r048) | Source URL On Free Registrar TLD | LOW | [Fetch and Execution](fetch-and-execution.md) |
| [R049](integrity.md#r049) | Compiler Plugin Or Loader Override | MEDIUM | [Integrity and Verification](integrity.md) |
| [R050](integrity.md#r050) | Compiler Hardening Disabled | MEDIUM | [Integrity and Verification](integrity.md) |
| [R051](fetch-and-execution.md#r051) | Network Access In pkgver | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [R052](install-and-persist.md#r052) | Dotfile Written To User Profile | HIGH | [Install and Persistence](install-and-persist.md) |
| [R053](install-and-persist.md#r053) | Setuid Or Setgid Bit Set In Package Root | MEDIUM | [Install and Persistence](install-and-persist.md) |
| [R054](install-and-persist.md#r054) | Persistence Unit Outside Package Root | HIGH | [Install and Persistence](install-and-persist.md) |
| [R055](fetch-and-execution.md#r055) | Git Clone With Variable Branch | MEDIUM | [Fetch and Execution](fetch-and-execution.md) |
| [R056](fetch-and-execution.md#r056) | Download Then Source | CRITICAL | [Fetch and Execution](fetch-and-execution.md) |
| [R057](fetch-and-execution.md#r057) | TLS Verification Disabled | HIGH | [Fetch and Execution](fetch-and-execution.md) |
| [R058](staging-and-recon.md#r058) | Write Outside Package Root | HIGH | [Staging and Reconnaissance](staging-and-recon.md) |
| [R059](install-and-persist.md#r059) | Setuid Or Setgid Bit Set Outside Package Root | HIGH | [Install and Persistence](install-and-persist.md) |
| [R144](install-and-persist.md#r144) | Packaged File Points At A World-Writable Path | HIGH | [Install and Persistence](install-and-persist.md) |
| [S001](sabotage.md#s001) | Recursive Self-Spawn | CRITICAL | [Sabotage](sabotage.md) |
| [S002](sabotage.md#s002) | Recursive Deletion Outside The Build Tree | CRITICAL | [Sabotage](sabotage.md) |
| [S003](sabotage.md#s003) | Raw Block Device Write | CRITICAL | [Sabotage](sabotage.md) |
| [S004](sabotage.md#s004) | Secure Deletion Of User Data | HIGH | [Sabotage](sabotage.md) |
| [S005](sabotage.md#s005) | Permission Change On A System Path | HIGH | [Sabotage](sabotage.md) |
| [S006](sabotage.md#s006) | System Service Disruption | HIGH | [Sabotage](sabotage.md) |
| [S007](sabotage.md#s007) | Cryptocurrency Miner | HIGH | [Sabotage](sabotage.md) |
| [S008](sabotage.md#s008) | Shell History Or Log Destruction | MEDIUM | [Sabotage](sabotage.md) |
| [W001](unverifiable.md#w001) | Executes Code This Analysis Did Not Read | INFO | [Unverifiable](unverifiable.md) |
| [W002](unverifiable.md#w002) | Build Resolves Dependencies From A Registry | INFO | [Unverifiable](unverifiable.md) |
| [W003](unverifiable.md#w003) | Applies A Patch This Analysis Did Not Read | INFO | [Unverifiable](unverifiable.md) |
| [W004](unverifiable.md#w004) | Build Engine Runs A Manifest This Analysis Did Not Read | INFO | [Unverifiable](unverifiable.md) |
| [W005](unverifiable.md#w005) | Build Runs A Target Whose Recipe Was Not Read | INFO | [Unverifiable](unverifiable.md) |
| [W006](unverifiable.md#w006) | Generated File Names A Build-Only Path | INFO | [Unverifiable](unverifiable.md) |
| [X001](crossfire.md#x001) | Encoded Payload Decoded And Executed | CRITICAL | [Crossfire](crossfire.md) |
| [X002](crossfire.md#x002) | Non-Literal Executable Name | CRITICAL | [Crossfire](crossfire.md) |
| [X003](crossfire.md#x003) | Obfuscated Command Argument | HIGH | [Crossfire](crossfire.md) |
| [X004](crossfire.md#x004) | Build Output Suppressed | MEDIUM | [Crossfire](crossfire.md) |
| [X005](crossfire.md#x005) | Home Reached By An Alternative Spelling | HIGH | [Crossfire](crossfire.md) |
| [X006](crossfire.md#x006) | Source Points Somewhere Unexpected | HIGH | [Crossfire](crossfire.md) |
| [X007](crossfire.md#x007) | Multiple Evasion Techniques | CRITICAL | [Crossfire](crossfire.md) |
| [X008](crossfire.md#x008) | Whitespace A Shell Does Not Split On | MEDIUM | [Crossfire](crossfire.md) |
| [X009](crossfire.md#x009) | Fetch Through An Uncatalogued Client | CRITICAL | [Crossfire](crossfire.md) |
| [X010](crossfire.md#x010) | Interpreter One-Liner Reaches The Network | HIGH | [Crossfire](crossfire.md) |
| [X011](crossfire.md#x011) | Package Manager Runs Fetched Code At Build Time | HIGH | [Crossfire](crossfire.md) |
| [X012](crossfire.md#x012) | Build Toolchain Redirected Into The Source Tree | HIGH | [Crossfire](crossfire.md) |
| [X013](crossfire.md#x013) | Fetch Redirected Or Trust Root Replaced | HIGH | [Crossfire](crossfire.md) |
| [X014](crossfire.md#x014) | Environment Variable Names Code To Run | HIGH | [Crossfire](crossfire.md) |
| [X015](crossfire.md#x015) | Work Scheduled To Run After The Build | HIGH | [Crossfire](crossfire.md) |
| [X016](crossfire.md#x016) | Fetch Piped Into An Unrecognised Consumer | HIGH | [Crossfire](crossfire.md) |
| [X017](crossfire.md#x017) | Tool Flag Or Builtin Carries A Command | HIGH | [Crossfire](crossfire.md) |
| [X018](crossfire.md#x018) | Interpreter One-Liner Assembles A Name | HIGH | [Crossfire](crossfire.md) |
| [X019](crossfire.md#x019) | Host Material Sent Or Packaged | HIGH | [Crossfire](crossfire.md) |
| [X020](crossfire.md#x020) | Recipe Writes The Build Steps The Engine Runs | HIGH | [Crossfire](crossfire.md) |
| [X021](crossfire.md#x021) | Executor Runs A File Chosen At Runtime | HIGH | [Crossfire](crossfire.md) |
| [X022](crossfire.md#x022) | Generated Config Handed To The Tool That Reads It | HIGH | [Crossfire](crossfire.md) |
| [X023](crossfire.md#x023) | Command Output Executed As A Script | HIGH | [Crossfire](crossfire.md) |
<!-- /generated: catalog -->

Weight-0 declared-practice findings (`P001` to `P008`) are not detections
and have no category. They are documented in
[the system reference](system.md#declared-practice).
