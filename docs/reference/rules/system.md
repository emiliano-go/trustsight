<!-- description: Compatibility landing for the former rule system reference: where scoring, matching, configuration, identifiers and every rule definition moved. -->

# Rule System Reference

This page used to hold the whole rule engine reference. It is now split by
subject so each subject has one owner:

- [Rule Scoring](../../rules/scoring.md): severity weights, score calculation,
  FATAL behaviour and review thresholds.
- [Rule Matching](../../rules/matching.md): `match_target`, scope, resolved
  versus raw-line matching and its limits.
- [Rule Configuration](../../rules/configuration.md): `rules.toml` fields,
  `config.toml` overrides, structural rules and enablement.
- [Rule Identifiers](../../rules/identifiers.md): reserved, retired and
  unassigned identifiers.
- [Rule Series](../../rules/series.md): mechanism definitions and
  series-specific detection behaviour.
- [Rules Overview](../../rules/index.md): the category and series indexes.
- [Individual Rule Definitions](../../rules/definitions.md): the full catalog.

## Compatibility anchors

Every rule anchor that used to live here still resolves. Follow the link to
the category page that now owns the definition.

### A001 {#a001}

See [A001: Setuid File In Artifact](../../rules/artifact.md#a001).

### A002 {#a002}

See [A002: Undeclared Unit In Artifact](../../rules/artifact.md#a002).

### A003 {#a003}

See [A003: Library Outside Depends](../../rules/artifact.md#a003).

### A004 {#a004}

See [A004: Install Hook Diverges From Declaration](../../rules/artifact.md#a004).

### A005 {#a005}

See [A005: Unusual Artifact Mode](../../rules/artifact.md#a005).

### A006 {#a006}

See [A006: File Capabilities In Artifact](../../rules/artifact.md#a006).

### A007 {#a007}

See [A007: Privileged Surface In Artifact](../../rules/artifact.md#a007).

### A008 {#a008}

See [A008: eBPF Artifact In Package](../../rules/artifact.md#a008).

### A009 {#a009}

See [A009: Executable Binary In Source Archive](../../rules/artifact.md#a009).

### A010 {#a010}

See [A010: Setuid File In Source Archive](../../rules/artifact.md#a010).

### A011 {#a011}

See [A011: Hook Runs On Every Transaction](../../rules/artifact.md#a011).

### A012 {#a012}

See [A012: Shipped Hook Or Udev Fetches Or Runs A User Path](../../rules/artifact.md#a012).

### A013 {#a013}

See [A013: Udev Rule Runs A Program](../../rules/artifact.md#a013).

### A014 {#a014}

See [A014: Unsafe ELF Runpath](../../rules/artifact.md#a014).

### A015 {#a015}

See [A015: Packed Or Encrypted ELF Section](../../rules/artifact.md#a015).

### A016 {#a016}

See [A016: Release Asset Diverges From Its Tag](../../rules/artifact.md#a016).

### C001 {#c001}

See [C001: Checksum Changed Without Source Change With Stable Version](../../rules/integrity.md#c001).

### C002 {#c002}

See [C002: Checksum Updated With Version Bump](../../rules/integrity.md#c002).

### C003 {#c003}

See [C003: Source URL Changed Without Version Bump](../../rules/integrity.md#c003).

### C004 {#c004}

See [C004: Checksum Removed For Unchanged Source](../../rules/integrity.md#c004).

### C005 {#c005}

See [C005: Binary Artifact From Untrusted Source](../../rules/integrity.md#c005).

### C006 {#c006}

See [C006: Maintainer Change With New Source Domain](../../rules/maintainer-and-metadata.md#c006).

### C007 {#c007}

See [C007: Command Substitution In Source Array](../../rules/fetch-and-execution.md#c007).

### C008 {#c008}

See [C008: Unread Content Moved Under A Stable Version](../../rules/integrity.md#c008).

### C009 {#c009}

See [C009: Unread Content Moved With The Version](../../rules/integrity.md#c009).

### C010 {#c010}

See [C010: Binary Metadata File](../../rules/integrity.md#c010).

### C011 {#c011}

See [C011: Prebuilt Binary From Non-Upstream Host](../../rules/integrity.md#c011).

### C012 {#c012}

See [C012: Source Domain Resembles Declared Upstream](../../rules/deception.md#c012).

### C013 {#c013}

See [C013: Source Fork Diverges From Declared Upstream](../../rules/integrity.md#c013).

### C014 {#c014}

See [C014: Array Order Manipulation](../../rules/integrity.md#c014).

### C015 {#c015}

See [C015: Fetch In package()](../../rules/fetch-and-execution.md#c015).

### C016 {#c016}

See [C016: Interpreter Invocation In Install Hook](../../rules/fetch-and-execution.md#c016).

### C017 {#c017}

See [C017: Install Hook Writes To A User-Writable Location](../../rules/install-and-persist.md#c017).

### C018 {#c018}

See [C018: Executable File Committed](../../rules/integrity.md#c018).

### C019 {#c019}

See [C019: File Renamed](../../rules/integrity.md#c019).

### C020 {#c020}

See [C020: Credentials In A Source URL](../../rules/integrity.md#c020).

### C021 {#c021}

See [C021: Dependency Removal During A Build Change](../../rules/composition.md#c021).

### C022 {#c022}

See [C022: Checksum Strength Downgraded](../../rules/integrity.md#c022).

### C023 {#c023}

See [C023: IP-Literal Source Host](../../rules/integrity.md#c023).

### C024 {#c024}

See [C024: Install Script Not Declared](../../rules/composition.md#c024).

### C025 {#c025}

See [C025: Hardening Option Disabled](../../rules/staging-and-recon.md#c025).

### C026 {#c026}

See [C026: Empty File Added](../../rules/integrity.md#c026).

### C027 {#c027}

See [C027: Declared Install Script Is Absent](../../rules/integrity.md#c027).

### C028 {#c028}

See [C028: Build Cache Outside The Build Trees](../../rules/staging-and-recon.md#c028).

### C029 {#c029}

See [C029: Backup Array Gains Entries](../../rules/install-and-persist.md#c029).

### C030 {#c030}

See [C030: Epoch Removed With Version Unchanged](../../rules/maintainer-and-metadata.md#c030).

### C031 {#c031}

See [C031: Boot Or System Image Tool Run During Build](../../rules/install-and-persist.md#c031).

### C032 {#c032}

See [C032: Scriptlet Executes Commands At Top Level](../../rules/install-and-persist.md#c032).

### C033 {#c033}

See [C033: Context Bleed](../../rules/integrity.md#c033).

### C034 {#c034}

See [C034: Metadata Inconsistency](../../rules/maintainer-and-metadata.md#c034).

### C035 {#c035}

See [C035: Owned Namespace Occupied](../../rules/integrity.md#c035).

### D001 {#d001}

See [D001: Novel Dependency Added](../../rules/naming-and-dependency.md#d001).

### D002 {#d002}

See [D002: Typosquatted Dependency](../../rules/naming-and-dependency.md#d002).

### D003 {#d003}

See [D003: New Network-Using Makedepends](../../rules/naming-and-dependency.md#d003).

### D004 {#d004}

See [D004: Dependency Hijack Via Provides](../../rules/naming-and-dependency.md#d004).

### D005 {#d005}

See [D005: Official-Repo Name Shadow](../../rules/naming-and-dependency.md#d005).

### E001 {#e001}

See [E001: Added-Text Compression Ratio](../../rules/entropy.md#e001).

### E002 {#e002}

See [E002: Encoded-Alphabet Fraction](../../rules/entropy.md#e002).

### E003 {#e003}

See [E003: Identifier Entropy](../../rules/entropy.md#e003).

### G001 {#g001}

See [G001: Shared Gained Host](../../rules/correlation.md#g001).

### G002 {#g002}

See [G002: Shared Added Literal](../../rules/correlation.md#g002).

### G003 {#g003}

See [G003: Coordinated Adoption](../../rules/correlation.md#g003).

### G004 {#g004}

See [G004: Shared Upstream Dependency](../../rules/correlation.md#g004).

### G005 {#g005}

See [G005: Impersonation Campaign](../../rules/correlation.md#g005).

### G006 {#g006}

See [G006: Neighborhood Under Campaign Alert](../../rules/correlation.md#g006).

### G007 {#g007}

See [G007: Campaign Corroboration](../../rules/correlation.md#g007).

### G008 {#g008}

See [G008: First-Seen Account Adoption Burst](../../rules/correlation.md#g008).

### G009 {#g009}

See [G009: Watchlisted Subject](../../rules/correlation.md#g009).

### G010 {#g010}

See [G010: Shared First-Seen Host](../../rules/correlation.md#g010).

### G011 {#g011}

See [G011: Maintainer Package Creation Burst](../../rules/correlation.md#g011).

### G012 {#g012}

See [G012: Shared Payload Signal](../../rules/correlation.md#g012).

### G013 {#g013}

See [G013: Shared Fetch Target](../../rules/correlation.md#g013).

### G014 {#g014}

See [G014: Shared Adoption Window](../../rules/correlation.md#g014).

### G015 {#g015}

See [G015: Sleeper Adoption Campaign](../../rules/correlation.md#g015).

### G016 {#g016}

See [G016: Account Blast Radius](../../rules/correlation.md#g016).

### H001 {#h001}

See [H001: Checksum Disabled](../../rules/integrity.md#h001).

### H002 {#h002}

See [H002: Checksum Emptied](../../rules/integrity.md#h002).

### H003 {#h003}

See [H003: Insecure Download Protocol](../../rules/fetch-and-execution.md#h003).

### H004 {#h004}

See [H004: Privilege Escalation](../../rules/fetch-and-execution.md#h004).

### H005 {#h005}

See [H005: validpgpkeys Added](../../rules/integrity.md#h005).

### H006 {#h006}

See [H006: New Make/Opt/Check Dependency](../../rules/naming-and-dependency.md#h006).

### H007 {#h007}

See [H007: Symlink Redirect](../../rules/staging-and-recon.md#h007).

### H008 {#h008}

See [H008: Suspicious Environment Variable](../../rules/integrity.md#h008).

### H009 {#h009}

See [H009: Network connection attempt](../../rules/fetch-and-execution.md#h009).

### H010 {#h010}

See [H010: Suspicious file write](../../rules/staging-and-recon.md#h010).

### H011 {#h011}

See [H011: Sensitive binary execution](../../rules/fetch-and-execution.md#h011).

### H012 {#h012}

See [H012: Strace detection attempt (TracerPid check)](../../rules/deception.md#h012).

### H013 {#h013}

See [H013: Strace log truncated (possible flood evasion)](../../rules/deception.md#h013).

### H014 {#h014}

See [H014: Eval or Exec Usage](../../rules/obfuscation.md#h014).

### H015 {#h015}

See [H015: Critical Build Function Modified](../../rules/fetch-and-execution.md#h015).

### H016 {#h016}

See [H016: Hidden Network Fetch In Build](../../rules/fetch-and-execution.md#h016).

### H017 {#h017}

See [H017: Install Hook Fetches Or Executes](../../rules/install-and-persist.md#h017).

### H018 {#h018}

See [H018: Patch Applied From Outside The Build Tree](../../rules/integrity.md#h018).

### H019 {#h019}

See [H019: Source URL Downgraded To HTTP](../../rules/integrity.md#h019).

### H020 {#h020}

See [H020: Very Recent Update](../../rules/temporal.md#h020).

### H021 {#h021}

See [H021: Brand New Package](../../rules/temporal.md#h021).

### H022 {#h022}

See [H022: Stale Package Revived](../../rules/temporal.md#h022).

### H023 {#h023}

See [H023: Install Hook Present](../../rules/install-and-persist.md#h023).

### H024 {#h024}

See [H024: GPG Verification Removed](../../rules/integrity.md#h024).

### H025 {#h025}

See [H025: Build Environment Subversion](../../rules/integrity.md#h025).

### H026 {#h026}

See [H026: New Maintainer Without Prior History](../../rules/maintainer-and-metadata.md#h026).

### H027 {#h027}

See [H027: Capability Density Anomaly](../../rules/composition.md#h027).

### H028 {#h028}

See [H028: Accelerated Release Cadence](../../rules/corpus-behavioral.md#h028).

### H029 {#h029-rule}

See [H029: Package-Name Typosquat](../../rules/naming-and-dependency.md#h029-rule).

### H030 {#h030-rule}

See [H030: Dependency-Set Expansion](../../rules/count-based.md#h030-rule).

### H031 {#h031}

See [H031: Version-In-URL Injection](../../rules/fetch-and-execution.md#h031).

### H032 {#h032}

See [H032: Write To User Home Or RC](../../rules/install-and-persist.md#h032).

### H033 {#h033}

See [H033: Moved Git Ref](../../rules/integrity.md#h033).

### H034 {#h034}

See [H034: Exotic Source Protocol](../../rules/fetch-and-execution.md#h034).

### H035 {#h035}

See [H035: Foreign Package Manager In Install Hook](../../rules/install-and-persist.md#h035).

### H036 {#h036}

See [H036: Shell Obfuscation Density](../../rules/count-based.md#h036).

### H037 {#h037}

See [H037: Long-Stable Property Changed](../../rules/maintainer-and-metadata.md#h037).

### H038 {#h038}

See [H038: World-Writable Staging](../../rules/staging-and-recon.md#h038).

### H039 {#h039}

See [H039: Systemd ExecStart From Runtime-Writable Path](../../rules/install-and-persist.md#h039).

### H040 {#h040}

See [H040: Host Reconnaissance](../../rules/staging-and-recon.md#h040).

### H041 {#h041}

See [H041: Upload To Paste Or File-Drop Host](../../rules/fetch-and-execution.md#h041).

### H042 {#h042}

See [H042: Hidden Drop](../../rules/staging-and-recon.md#h042).

### H043 {#h043}

See [H043: Attack-Chain Composition](../../rules/composition.md#h043).

### H044 {#h044}

See [H044: Ownership Transition](../../rules/maintainer-and-metadata.md#h044).

### H045 {#h045}

See [H045: Mass Adoption](../../rules/count-based.md#h045).

### H046 {#h046}

See [H046: Orphan/Adoption Dependency](../../rules/corpus-behavioral.md#h046).

### H047 {#h047}

See [H047: Security-Relevant Build Flag Change](../../rules/integrity.md#h047).

### H048 {#h048}

See [H048: Dependency Vendored Into Source](../../rules/naming-and-dependency.md#h048).

### H049 {#h049}

See [H049: Source Origin Changed](../../rules/maintainer-and-metadata.md#h049).

### H050 {#h050}

See [H050: Version Scheme Changed](../../rules/maintainer-and-metadata.md#h050).

### H051 {#h051}

See [H051: Package Description Changed](../../rules/maintainer-and-metadata.md#h051).

### H052 {#h052}

See [H052: Shared Source Repository](../../rules/count-based.md#h052).

### H053 {#h053}

See [H053: Name/Host Consensus Divergence](../../rules/naming-and-dependency.md#h053).

### H054 {#h054}

See [H054: Build System Changed](../../rules/maintainer-and-metadata.md#h054).

### H055 {#h055}

See [H055: Attribute Burst](../../rules/count-based.md#h055).

### H056 {#h056}

See [H056: Known Indicator of Compromise](../../rules/indicator.md#h056).

### H057 {#h057}

See [H057: Transitive Exposure](../../rules/corpus-behavioral.md#h057).

### H058 {#h058}

See [H058: Maintainer Baseline Deviation](../../rules/maintainer-and-metadata.md#h058).

### H059 {#h059}

See [H059: Name/Repo Divergence](../../rules/naming-and-dependency.md#h059).

### H060 {#h060}

See [H060: Transitive Orphan Risk](../../rules/corpus-behavioral.md#h060).

### H061 {#h061}

See [H061: Dependency Centrality](../../rules/corpus-behavioral.md#h061).

### H062 {#h062}

See [H062: Pacman Hook Installed](../../rules/install-and-persist.md#h062).

### H063 {#h063}

See [H063: Epoch Introduced](../../rules/maintainer-and-metadata.md#h063).

### H064 {#h064}

See [H064: Provides/Replaces Scope Expansion](../../rules/naming-and-dependency.md#h064).

### H065 {#h065}

See [H065: Obfuscated Literal Reconstructed](../../rules/obfuscation.md#h065).

### H066 {#h066}

See [H066: Embedded Binary In Tree](../../rules/integrity.md#h066).

### H067 {#h067}

See [H067: Anti-Analysis Check](../../rules/deception.md#h067).

### H068 {#h068}

See [H068: Reconstructed Executable Payload](../../rules/fetch-and-execution.md#h068).

### H069 {#h069}

See [H069: Build-time Generation Then Execution](../../rules/fetch-and-execution.md#h069).

### H070 {#h070}

See [H070: Archive Trailer Anomaly](../../rules/integrity.md#h070).

### H071 {#h071}

See [H071: Covert Egress](../../rules/fetch-and-execution.md#h071).

### H072 {#h072}

See [H072: Write Then Execute](../../rules/fetch-and-execution.md#h072).

### H073 {#h073}

See [H073: Introduction Rate Deviation](../../rules/corpus-behavioral.md#h073).

### H074 {#h074}

See [H074: Adopt-then-Modify](../../rules/maintainer-and-metadata.md#h074).

### H075 {#h075}

See [H075: Remote Script Via Process Substitution](../../rules/fetch-and-execution.md#h075).

### H076 {#h076}

See [H076: Build Writes Outside Staging Root](../../rules/staging-and-recon.md#h076).

### H077 {#h077}

See [H077: Parse-time Network Fetch](../../rules/fetch-and-execution.md#h077).

### H078 {#h078}

See [H078: Signing Key Set Changed](../../rules/integrity.md#h078).

### H079 {#h079}

See [H079: Build Flags Weakened](../../rules/integrity.md#h079).

### H080 {#h080}

See [H080: Indirect Command Expansion](../../rules/obfuscation.md#h080).

### H081 {#h081}

See [H081: Committed File Executed Without Declaration](../../rules/fetch-and-execution.md#h081).

### H082 {#h082}

See [H082: Fetch Then Execute](../../rules/fetch-and-execution.md#h082).

### H083 {#h083}

See [H083: Downloaded Source File Executed](../../rules/fetch-and-execution.md#h083).

### H084 {#h084}

See [H084: Service ExecStart Targets Undeclared Binary](../../rules/install-and-persist.md#h084).

### H085 {#h085}

See [H085: PATH Injection With Undeclared Directory](../../rules/staging-and-recon.md#h085).

### H086 {#h086}

See [H086: Adopted From Orphan](../../rules/maintainer-and-metadata.md#h086).

### H087 {#h087}

See [H087: Recipe Changed Without Upstream](../../rules/integrity.md#h087).

### H088 {#h088}

See [H088: Adopted, Recipe Rewritten, Unpinned Fetch](../../rules/maintainer-and-metadata.md#h088).

### H089 {#h089}

See [H089: Packaged File Names A Build-Only Path](../../rules/install-and-persist.md#h089).

### H090 {#h090}

See [H090: Committed Companion Carries A Fetch-Execute Payload](../../rules/fetch-and-execution.md#h090).

### H091 {#h091}

See [H091: Checksum Array Shorter Than Source Array](../../rules/integrity.md#h091).

### H092 {#h092}

See [H092: Metadata Names A Source The Recipe Does Not](../../rules/integrity.md#h092).

### H093 {#h093}

See [H093: Committed Config Points At A Build-Only Path](../../rules/install-and-persist.md#h093).

### H094 {#h094}

See [H094: Unread Script Executed During Packaging](../../rules/fetch-and-execution.md#h094).

### H095 {#h095}

See [H095: Boot Or Image Artifact Built From The Source Tree](../../rules/install-and-persist.md#h095).

### H096 {#h096}

See [H096: Download Agent Override](../../rules/integrity.md#h096).

### H097 {#h097}

See [H097: Function Shadowing](../../rules/integrity.md#h097).

### H098 {#h098}

See [H098: Naming/Deception Cluster](../../rules/composition.md#h098).

### H099 {#h099}

See [H099: Source Host Swapped Under A Kept Local Name](../../rules/integrity.md#h099).

### H100 {#h100}

See [H100: Install Hook Added Or Retargeted](../../rules/install-and-persist.md#h100).

### H101 {#h101}

See [H101: Source Pinning Lost](../../rules/integrity.md#h101).

### H102 {#h102}

See [H102: Maintainer Change With Signing Key Change](../../rules/composition.md#h102).

### H103 {#h103}

See [H103: Metadata And Recipe Disagree](../../rules/integrity.md#h103).

### H104 {#h104}

See [H104: Placeholder Package](../../rules/naming-and-dependency.md#h104).

### H105 {#h105}

See [H105: Adopted Source Executed](../../rules/maintainer-and-metadata.md#h105).

### H106 {#h106}

See [H106: Registry Or Index Override](../../rules/naming-and-dependency.md#h106).

### H107 {#h107}

See [H107: Credential Store Access With Egress](../../rules/fetch-and-execution.md#h107).

### H108 {#h108}

See [H108: Service Or Cron Enable Command](../../rules/install-and-persist.md#h108).

### H109 {#h109}

See [H109: Build Helper Executed From A Secondary Source](../../rules/fetch-and-execution.md#h109).

### M001 {#m001}

See [M001: Claim Contradicted By Structure](../../rules/meta.md#m001).

### M002 {#m002}

See [M002: Weak Signal Across Layers](../../rules/meta.md#m002).

### M003 {#m003}

See [M003: Composition Not Owned Elsewhere](../../rules/meta.md#m003).

### M004 {#m004}

See [M004: Expected Co-fire Absent](../../rules/meta.md#m004).

### M005 {#m005}

See [M005: Licensor Absent On Licensed Shape](../../rules/meta.md#m005).

### M006 {#m006}

See [M006: Campaign Re-armed Too Often](../../rules/meta.md#m006).

### R001 {#r001}

See [R001: Remote Script Execution](../../rules/fetch-and-execution.md#r001).

### R002 {#r002}

See [R002: Wget Pipe to Shell](../../rules/fetch-and-execution.md#r002).

### R003 {#r003}

See [R003: Base64 Decode and Execute](../../rules/obfuscation.md#r003).

### R007 {#r007}

See [R007: Install File Modification](../../rules/install-and-persist.md#r007).

### R008 {#r008}

See [R008: Unexpected File Download](../../rules/fetch-and-execution.md#r008).

### R010 {#r010}

See [R010: Uses curl in PKGBUILD](../../rules/fetch-and-execution.md#r010).

### R011 {#r011}

See [R011: Uses wget in PKGBUILD](../../rules/fetch-and-execution.md#r011).

### R012 {#r012}

See [R012: LLM Prompt Injection](../../rules/deception.md#r012).

### R013 {#r013}

See [R013: Unicode Bidi Override](../../rules/deception.md#r013).

### R017 {#r017}

See [R017: Setuid/Setgid Permission](../../rules/install-and-persist.md#r017).

### R039 {#r039}

See [R039: Eval With Dynamic Content](../../rules/obfuscation.md#r039).

### R040 {#r040}

See [R040: Shell -c With Dynamic Payload](../../rules/obfuscation.md#r040).

### R041 {#r041}

See [R041: Shell Network Redirection](../../rules/fetch-and-execution.md#r041).

### R042 {#r042}

See [R042: Download Then Execute](../../rules/fetch-and-execution.md#r042).

### R043 {#r043}

See [R043: Base64 Blob Decode](../../rules/obfuscation.md#r043).

### R044 {#r044}

See [R044: Interpreter One-Liner With Network](../../rules/fetch-and-execution.md#r044).

### R045 {#r045}

See [R045: Binary Encoding Pipe](../../rules/obfuscation.md#r045).

### R046 {#r046}

See [R046: Source URL Uses IP Address](../../rules/fetch-and-execution.md#r046).

### R047 {#r047}

See [R047: Source URL Uses Non-Standard Port](../../rules/fetch-and-execution.md#r047).

### R048 {#r048}

See [R048: Source URL On Free Registrar TLD](../../rules/fetch-and-execution.md#r048).

### R049 {#r049}

See [R049: Compiler Plugin Or Loader Override](../../rules/integrity.md#r049).

### R050 {#r050}

See [R050: Compiler Hardening Disabled](../../rules/integrity.md#r050).

### R051 {#r051}

See [R051: Network Access In pkgver](../../rules/fetch-and-execution.md#r051).

### R052 {#r052}

See [R052: Dotfile Written To User Profile](../../rules/install-and-persist.md#r052).

### R053 {#r053}

See [R053: Setuid Or Setgid Bit Set In Package Root](../../rules/install-and-persist.md#r053).

### R054 {#r054}

See [R054: Persistence Unit Outside Package Root](../../rules/install-and-persist.md#r054).

### R055 {#r055}

See [R055: Git Clone With Variable Branch](../../rules/fetch-and-execution.md#r055).

### R056 {#r056}

See [R056: Download Then Source](../../rules/fetch-and-execution.md#r056).

### R057 {#r057}

See [R057: TLS Verification Disabled](../../rules/fetch-and-execution.md#r057).

### R058 {#r058}

See [R058: Write Outside Package Root](../../rules/staging-and-recon.md#r058).

### R059 {#r059}

See [R059: Setuid Or Setgid Bit Set Outside Package Root](../../rules/install-and-persist.md#r059).

### R078 {#r078}

See [R078: Compression Command Override](../../rules/integrity.md#r078).

### R091 {#r091}

See [R091: Privilege Escalation Override](../../rules/integrity.md#r091).

### R099 {#r099}

See [R099: Trap Statement](../../rules/integrity.md#r099).

### R104 {#r104}

See [R104: Error Handling Suppressed](../../rules/integrity.md#r104).

### R144 {#r144}

See [R144: Packaged File Points At A World-Writable Path](../../rules/install-and-persist.md#r144).

### R152 {#r152}

See [R152: Source URL On Free-Hosting Or Dynamic-DNS Host](../../rules/fetch-and-execution.md#r152).

### S001 {#s001}

See [S001: Recursive Self-Spawn](../../rules/sabotage.md#s001).

### S002 {#s002}

See [S002: Recursive Deletion Outside The Build Tree](../../rules/sabotage.md#s002).

### S003 {#s003}

See [S003: Raw Block Device Write](../../rules/sabotage.md#s003).

### S004 {#s004}

See [S004: Secure Deletion Of User Data](../../rules/sabotage.md#s004).

### S005 {#s005}

See [S005: Permission Change On A System Path](../../rules/sabotage.md#s005).

### S006 {#s006}

See [S006: System Service Disruption](../../rules/sabotage.md#s006).

### S007 {#s007}

See [S007: Cryptocurrency Miner](../../rules/sabotage.md#s007).

### S008 {#s008}

See [S008: Shell History Or Log Destruction](../../rules/sabotage.md#s008).

### S009 {#s009}

See [S009: Privileged Account Or udev Rule](../../rules/sabotage.md#s009).

### S010 {#s010}

See [S010: Kernel Module Loaded During Build](../../rules/sabotage.md#s010).

### S011 {#s011}

See [S011: Self-Referential Payload Teardown](../../rules/sabotage.md#s011).

### T001 {#t001}

See [T001: Signing-Key Novelty](../../rules/temporal.md#t001).

### T002 {#t002}

See [T002: Maintainer Domain Novelty](../../rules/temporal.md#t002).

### T003 {#t003}

See [T003: Signing Key Rotated](../../rules/temporal.md#t003).

### T004 {#t004}

See [T004: Vouch Surface Removed](../../rules/temporal.md#t004).

### T005 {#t005}

See [T005: Scheme Downgrade](../../rules/temporal.md#t005).

### T006 {#t006}

See [T006: Metadata-Git Divergence](../../rules/temporal.md#t006).

### T007 {#t007}

See [T007: Packager Not In History](../../rules/temporal.md#t007).

### T008 {#t008}

See [T008: Delayed Payload Adoption](../../rules/temporal.md#t008).

### T009 {#t009}

See [T009: High-Value Dormant Takeover](../../rules/temporal.md#t009).

### T010 {#t010}

See [T010: Dependency Redirection](../../rules/naming-and-dependency.md#t010).

### T011 {#t011}

See [T011: Package Reappearance](../../rules/temporal.md#t011).

### T012 {#t012}

See [T012: Trust Erosion Sequence](../../rules/temporal.md#t012).

### U001 {#u001}

See [U001: Manifest Added Or Removed](../../rules/upstream-manifests.md#u001).

### U002 {#u002}

See [U002: Upstream Dependency Delta](../../rules/upstream-manifests.md#u002).

### U003 {#u003}

See [U003: New Remote Source In Manifest](../../rules/upstream-manifests.md#u003).

### U004 {#u004}

See [U004: Registry Redirect](../../rules/upstream-manifests.md#u004).

### U005 {#u005}

See [U005: Dependency Surface Jump](../../rules/upstream-manifests.md#u005).

### U006 {#u006}

See [U006: Manifest Changed Without Its Lockfile](../../rules/upstream-manifests.md#u006).

### U007 {#u007}

See [U007: CI Exfil Shape](../../rules/upstream-release.md#u007).

### U008 {#u008}

See [U008: Git-History Credential Sweep](../../rules/upstream-release.md#u008).

### U009 {#u009}

See [U009: New CI Surface Committed](../../rules/upstream-release.md#u009).

### U010 {#u010}

See [U010: Unauditable Upstream](../../rules/upstream-release.md#u010).

### U011 {#u011}

See [U011: Upstream Origin Changed](../../rules/upstream-manifests.md#u011).

### U012 {#u012}

See [U012: Lockfile Integrity Weakened](../../rules/upstream-manifests.md#u012).

### U013 {#u013}

See [U013: CI Exfil Shape (Local)](../../rules/upstream-release.md#u013).

### U014 {#u014}

See [U014: Git-History Credential Sweep (Local)](../../rules/upstream-release.md#u014).

### U015 {#u015}

See [U015: Federated Upstream Manifest Delta](../../rules/upstream-manifests.md#u015).

### W001 {#w001}

See [W001: Executes Code This Analysis Did Not Read](../../rules/unverifiable.md#w001).

### W002 {#w002}

See [W002: Build Resolves Dependencies From A Registry](../../rules/unverifiable.md#w002).

### W003 {#w003}

See [W003: Applies A Patch This Analysis Did Not Read](../../rules/unverifiable.md#w003).

### W004 {#w004}

See [W004: Build Engine Runs A Manifest This Analysis Did Not Read](../../rules/unverifiable.md#w004).

### W005 {#w005}

See [W005: Build Runs A Target Whose Recipe Was Not Read](../../rules/unverifiable.md#w005).

### W006 {#w006}

See [W006: Generated File Names A Build-Only Path](../../rules/unverifiable.md#w006).

### W007 {#w007}

See [W007: Dependency Novelty Declined For Insufficient Observations](../../rules/unverifiable.md#w007).

### W008 {#w008}

See [W008: Unresolved Construct In A Recipe](../../rules/unverifiable.md#w008).

### W009 {#w009}

See [W009: Upstream Manifests Not Examined](../../rules/unverifiable.md#w009).

### W010 {#w010}

See [W010: Alert Volume Capped](../../rules/unverifiable.md#w010).

### W011 {#w011}

See [W011: Upstream Content Not Read](../../rules/unverifiable.md#w011).

### W012 {#w012}

See [W012: Federation Not Consulted](../../rules/unverifiable.md#w012).

### W013 {#w013}

See [W013: Campaign Perimeter Boundary Note](../../rules/unverifiable.md#w013).

### W014 {#w014}

See [W014: Upstream Scan Not Completed](../../rules/unverifiable.md#w014).

### W015 {#w015}

See [W015: Archive Structure Ambiguous](../../rules/unverifiable.md#w015).

### X001 {#x001}

See [X001: Encoded Payload Decoded And Executed](../../rules/crossfire.md#x001).

### X002 {#x002}

See [X002: Non-Literal Executable Name](../../rules/crossfire.md#x002).

### X003 {#x003}

See [X003: Obfuscated Command Argument](../../rules/crossfire.md#x003).

### X004 {#x004}

See [X004: Build Output Suppressed](../../rules/crossfire.md#x004).

### X005 {#x005}

See [X005: Home Reached By An Alternative Spelling](../../rules/crossfire.md#x005).

### X006 {#x006}

See [X006: Source Points Somewhere Unexpected](../../rules/crossfire.md#x006).

### X007 {#x007}

See [X007: Multiple Evasion Techniques](../../rules/crossfire.md#x007).

### X008 {#x008}

See [X008: Whitespace A Shell Does Not Split On](../../rules/crossfire.md#x008).

### X009 {#x009}

See [X009: Fetch Through An Uncatalogued Client](../../rules/crossfire.md#x009).

### X010 {#x010}

See [X010: Interpreter One-Liner Reaches The Network](../../rules/crossfire.md#x010).

### X011 {#x011}

See [X011: Package Manager Runs Fetched Code At Build Time](../../rules/crossfire.md#x011).

### X012 {#x012}

See [X012: Build Toolchain Redirected Into The Source Tree](../../rules/crossfire.md#x012).

### X013 {#x013}

See [X013: Fetch Redirected Or Trust Root Replaced](../../rules/crossfire.md#x013).

### X014 {#x014}

See [X014: Environment Variable Names Code To Run](../../rules/crossfire.md#x014).

### X015 {#x015}

See [X015: Work Scheduled To Run After The Build](../../rules/crossfire.md#x015).

### X016 {#x016}

See [X016: Fetch Piped Into An Unrecognised Consumer](../../rules/crossfire.md#x016).

### X017 {#x017}

See [X017: Tool Flag Or Builtin Carries A Command](../../rules/crossfire.md#x017).

### X018 {#x018}

See [X018: Interpreter One-Liner Assembles A Name](../../rules/crossfire.md#x018).

### X019 {#x019}

See [X019: Host Material Sent Or Packaged](../../rules/crossfire.md#x019).

### X020 {#x020}

See [X020: Recipe Writes The Build Steps The Engine Runs](../../rules/crossfire.md#x020).

### X021 {#x021}

See [X021: Executor Runs A File Chosen At Runtime](../../rules/crossfire.md#x021).

### X022 {#x022}

See [X022: Generated Config Handed To The Tool That Reads It](../../rules/crossfire.md#x022).

### X023 {#x023}

See [X023: Command Output Executed As A Script](../../rules/crossfire.md#x023).

### X024 {#x024}

See [X024: Indirect Sensitive Assignment](../../rules/crossfire.md#x024).

### X025 {#x025}

See [X025: Multi-Line Function Shadow](../../rules/crossfire.md#x025).

### X026 {#x026}

See [X026: Unresolved Constructs In Executable Positions](../../rules/crossfire.md#x026).

### X027 {#x027}

See [X027: Refusal Cluster](../../rules/crossfire.md#x027).

### X028 {#x028}

See [X028: Pattern Completed Across Commits](../../rules/crossfire.md#x028).

### X029 {#x029}

See [X029: Encoded Material At Rest](../../rules/crossfire.md#x029).

### X030 {#x030}

See [X030: ANSI-C Quoted Content In Commands](../../rules/crossfire.md#x030).

### X031 {#x031}

See [X031: Build Reads Non-Code Text](../../rules/crossfire.md#x031).

### X032 {#x032}

See [X032: Command Name Assembled By Splicing](../../rules/crossfire.md#x032).

### X033 {#x033}

See [X033: File With No Provenance Executed](../../rules/crossfire.md#x033).

### X034 {#x034}

See [X034: Fetch Laundered Through An Archival Service](../../rules/crossfire.md#x034).
