<!-- description: Generated coverage map: every shipped rule, its layer, claim category, CWE, weight state and known gap. -->
<!-- generated: threat-coverage -->

# Threat coverage

This page is generated from the shipped registry by
`scripts/build_threat_coverage.py`. It is a map of what the rules claim, not a
claim of complete coverage.

| Rule | Name | Category | Layer | Severity | Weight | CWE | Boundary |
|---|---|---|---|---|---|---|---|
| A001 | Setuid File In Artifact | artifact |  | HIGH | 25 | CWE-250 |  |
| A002 | Undeclared Unit In Artifact | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A003 | Library Outside Depends | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A004 | Install Hook Diverges From Declaration | artifact |  | HIGH | 25 | CWE-506 |  |
| A005 | Unusual Artifact Mode | artifact |  | INFO | 0 | CWE-506 |  |
| A006 | File Capabilities In Artifact | artifact |  | HIGH | 25 | CWE-250 |  |
| A007 | Privileged Surface In Artifact | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A008 | eBPF Artifact In Package | artifact |  | HIGH | 25 | CWE-506 |  |
| A009 | Executable Binary In Source Archive | artifact |  | HIGH | 25 | CWE-506 |  |
| A010 | Setuid File In Source Archive | artifact |  | HIGH | 25 | CWE-250 |  |
| A011 | Hook Runs On Every Transaction | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| A012 | Shipped Hook Or Udev Fetches Or Runs A User Path | artifact |  | HIGH | 0 (anergic) | CWE-506 | calibration |
| A013 | Udev Rule Runs A Program | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| A014 | Unsafe ELF Runpath | artifact |  | HIGH | 0 (anergic) | CWE-506 | calibration |
| A015 | Packed Or Encrypted ELF Section | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| C001 | Checksum Changed Without Source Change With Stable Version | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C002 | Checksum Updated With Version Bump | integrity | L1 | INFO | 0 | CWE-354 |  |
| C003 | Source URL Changed Without Version Bump | integrity | L1 | INFO | 0 | CWE-354 |  |
| C004 | Checksum Removed For Unchanged Source | integrity | L1 | CRITICAL | 40 | CWE-354 |  |
| C005 | Binary Artifact From Untrusted Source | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C006 | Maintainer Change With New Source Domain | maintainer-and-metadata | L1 | HIGH | 25 | CWE-290 |  |
| C007 | Command Substitution In Source Array | fetch-and-execution | L1 | CRITICAL | 40 | CWE-94 |  |
| C008 | Unread Content Moved Under A Stable Version | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C009 | Unread Content Moved With The Version | integrity | L1 | INFO | 0 | CWE-354 |  |
| C010 | Binary Metadata File | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C011 | Prebuilt Binary From Non-Upstream Host | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C012 | Source Domain Resembles Declared Upstream | deception | L1 | MEDIUM | 15 | CWE-506 |  |
| C013 | Source Fork Diverges From Declared Upstream | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C014 | Array Order Manipulation | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C015 | Fetch In package() | fetch-and-execution | L1 | HIGH | 25 | CWE-94 |  |
| C016 | Interpreter Invocation In Install Hook | fetch-and-execution | L1 | HIGH | 25 | CWE-94 |  |
| C017 | Install Hook Writes To A User-Writable Location | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C018 | Executable File Committed | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C019 | File Renamed | integrity | L1 | INFO | 0 | CWE-354 |  |
| C020 | Credentials In A Source URL | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C021 | Dependency Removal During A Build Change | composition | L1 | HIGH | 25 | CWE-506 |  |
| C022 | Checksum Strength Downgraded | integrity | L1 | HIGH | 25 | CWE-328 |  |
| C023 | IP-Literal Source Host | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C024 | Install Script Not Declared | composition | L1 | MEDIUM | 15 | CWE-506 |  |
| C025 | Hardening Option Disabled | staging-and-recon | L1 | LOW | 5 | CWE-506 |  |
| C026 | Empty File Added | integrity | L1 | INFO | 0 | CWE-354 |  |
| C027 | Declared Install Script Is Absent | integrity | L1 | INFO | 0 | CWE-354 |  |
| C028 | Build Cache Outside The Build Trees | staging-and-recon | L1 | None | 0 | CWE-506 |  |
| C029 | Backup Array Gains Entries | install-and-persist | L1 | INFO | 0 | CWE-506 |  |
| C030 | Epoch Removed With Version Unchanged | maintainer-and-metadata | L1 | INFO | 0 | CWE-290 |  |
| C031 | Boot Or System Image Tool Run During Build | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C032 | Scriptlet Executes Commands At Top Level | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C033 | Context Bleed | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C034 | Metadata Inconsistency | maintainer-and-metadata | L1 | INFO | 0 | CWE-290 |  |
| C035 | Owned Namespace Occupied | integrity | L1 | HIGH | 0 (anergic) | CWE-354 | calibration |
| D001 | Novel Dependency Added | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| D002 | Typosquatted Dependency | naming-and-dependency | L6 | HIGH | 25 | CWE-427 |  |
| D003 | New Network-Using Makedepends | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| D004 | Dependency Hijack Via Provides | naming-and-dependency | L6 | HIGH | 25 | CWE-427 |  |
| D005 | Official-Repo Name Shadow | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| E001 | Added-Text Compression Ratio | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| E002 | Encoded-Alphabet Fraction | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| E003 | Identifier Entropy | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| G001 | Shared Gained Host | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G002 | Shared Added Literal | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G003 | Coordinated Adoption | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| G004 | Shared Upstream Dependency | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G005 | Impersonation Campaign | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G006 | Neighborhood Under Campaign Alert | correlation | L8 | INFO | 0 | CWE-506 |  |
| G007 | Campaign Corroboration | correlation | L8 | INFO | 0 | CWE-506 |  |
| G008 | First-Seen Account Adoption Burst | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G009 | Watchlisted Subject | correlation | L8 | INFO | 0 | CWE-506 |  |
| G010 | Shared First-Seen Host | correlation | L8 | INFO | 0 | CWE-506 |  |
| G011 | Maintainer Package Creation Burst | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| G012 | Shared Payload Signal | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G013 | Shared Fetch Target | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G014 | Shared Adoption Window | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G015 | Sleeper Adoption Campaign | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| H001 | Checksum Disabled | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H002 | Checksum Emptied | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H003 | Insecure Download Protocol | fetch-and-execution | L5 | LOW | 5 | CWE-94 |  |
| H004 | Privilege Escalation | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H005 | validpgpkeys Added | integrity | L5 | None | 0 | CWE-354 |  |
| H006 | New Make/Opt/Check Dependency | naming-and-dependency | L5 | None | 0 | CWE-427 |  |
| H007 | Symlink Redirect | staging-and-recon | L5 | None | 0 | CWE-506 |  |
| H008 | Suspicious Environment Variable | integrity | L5 | None | 0 | CWE-354 |  |
| H009 | Network connection attempt | fetch-and-execution | L5 | None | 0 | CWE-94 |  |
| H010 | Suspicious file write | staging-and-recon | L5 | None | 0 | CWE-506 |  |
| H011 | Sensitive binary execution | fetch-and-execution | L5 | None | 0 | CWE-94 |  |
| H012 | Strace detection attempt (TracerPid check) | deception | L5 | None | 0 | CWE-506 |  |
| H013 | Strace log truncated (possible flood evasion) | deception | L5 | None | 0 | CWE-506 |  |
| H014 | Eval or Exec Usage | obfuscation | L5 | None | 0 | CWE-506 |  |
| H015 | Critical Build Function Modified | fetch-and-execution | L5 | INFO | 0 | CWE-94 |  |
| H016 | Hidden Network Fetch In Build | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H017 | Install Hook Fetches Or Executes | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H018 | Patch Applied From Outside The Build Tree | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H019 | Source URL Downgraded To HTTP | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H020 | Very Recent Update | temporal | L6 | INFO | 0 | CWE-506 |  |
| H021 | Brand New Package | temporal | L6 | INFO | 0 | CWE-506 |  |
| H022 | Stale Package Revived | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| H023 | Install Hook Present | install-and-persist | L5 | INFO | 0 | CWE-506 |  |
| H024 | GPG Verification Removed | integrity | L5 | HIGH | 25 | CWE-347 |  |
| H025 | Build Environment Subversion | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H026 | New Maintainer Without Prior History | maintainer-and-metadata | L6 | HIGH | 25 | CWE-290 |  |
| H027 | Capability Density Anomaly | composition | L5 | INFO | 0 | CWE-506 |  |
| H028 | Accelerated Release Cadence | corpus-behavioral | L6 | None | 0 | CWE-506 |  |
| H029 | Package-Name Typosquat | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H030 | Dependency-Set Expansion | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H031 | Version-In-URL Injection | fetch-and-execution | L5 | MEDIUM | 15 | CWE-94 |  |
| H032 | Write To User Home Or RC | install-and-persist | L5 | CRITICAL | 40 | CWE-506 |  |
| H033 | Moved Git Ref | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H034 | Exotic Source Protocol | fetch-and-execution | L5 | MEDIUM | 15 | CWE-94 |  |
| H035 | Foreign Package Manager In Install Hook | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H036 | Shell Obfuscation Density | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H037 | Long-Stable Property Changed | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H038 | World-Writable Staging | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H039 | Systemd ExecStart From Runtime-Writable Path | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H040 | Host Reconnaissance | staging-and-recon | L5 | INFO | 0 | CWE-506 |  |
| H041 | Upload To Paste Or File-Drop Host | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H042 | Hidden Drop | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H043 | Attack-Chain Composition | composition | L5 | INFO | 0 | CWE-506 |  |
| H044 | Ownership Transition | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H045 | Mass Adoption | count-based | L6 | HIGH | 25 | CWE-506 |  |
| H046 | Orphan/Adoption Dependency | corpus-behavioral | L6 | MEDIUM | 15 | CWE-506 |  |
| H047 | Security-Relevant Build Flag Change | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H048 | Dependency Vendored Into Source | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H049 | Source Origin Changed | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H050 | Version Scheme Changed | maintainer-and-metadata | L5 | INFO | 0 | CWE-290 |  |
| H051 | Package Description Changed | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H052 | Shared Source Repository | count-based | L5 | HIGH | 25 | CWE-506 |  |
| H053 | Name/Host Consensus Divergence | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H054 | Build System Changed | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H055 | Attribute Burst | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H056 | Known Indicator of Compromise | indicator | L7 | FATAL | 0 | CWE-506 |  |
| H057 | Transitive Exposure | corpus-behavioral | L5 | INFO | 0 | CWE-506 |  |
| H058 | Maintainer Baseline Deviation | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H059 | Name/Repo Divergence | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H060 | Transitive Orphan Risk | corpus-behavioral | L6 | INFO | 0 | CWE-506 |  |
| H061 | Dependency Centrality | corpus-behavioral | L5 | INFO | 0 | CWE-506 |  |
| H062 | Pacman Hook Installed | install-and-persist | L5 | MEDIUM | 15 | CWE-506 |  |
| H063 | Epoch Introduced | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H064 | Provides/Replaces Scope Expansion | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H065 | Obfuscated Literal Reconstructed | obfuscation | L5 | INFO | 0 | CWE-506 |  |
| H066 | Embedded Binary In Tree | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H067 | Anti-Analysis Check | deception | L5 | HIGH | 25 | CWE-506 |  |
| H068 | Reconstructed Executable Payload | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H069 | Build-time Generation Then Execution | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H070 | Archive Trailer Anomaly | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H071 | Covert Egress | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H072 | Write Then Execute | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H073 | Introduction Rate Deviation | corpus-behavioral | L6 | MEDIUM | 15 | CWE-506 |  |
| H074 | Adopt-then-Modify | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H075 | Remote Script Via Process Substitution | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H076 | Build Writes Outside Staging Root | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H077 | Parse-time Network Fetch | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H078 | Signing Key Set Changed | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H079 | Build Flags Weakened | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H080 | Indirect Command Expansion | obfuscation | L5 | CRITICAL | 40 | CWE-506 |  |
| H081 | Committed File Executed Without Declaration | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H082 | Fetch Then Execute | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H083 | Downloaded Source File Executed | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H084 | Service ExecStart Targets Undeclared Binary | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H085 | PATH Injection With Undeclared Directory | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H086 | Adopted From Orphan | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H087 | Recipe Changed Without Upstream | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H088 | Adopted, Recipe Rewritten, Unpinned Fetch | maintainer-and-metadata | L6 | HIGH | 25 | CWE-290 |  |
| H089 | Packaged File Names A Build-Only Path | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H090 | Committed Companion Carries A Fetch-Execute Payload | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H091 | Checksum Array Shorter Than Source Array | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H092 | Metadata Names A Source The Recipe Does Not | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H093 | Committed Config Points At A Build-Only Path | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H094 | Unread Script Executed During Packaging | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H095 | Boot Or Image Artifact Built From The Source Tree | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H096 | Download Agent Override | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H097 | Function Shadowing | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H098 | Naming/Deception Cluster | composition | L5 | HIGH | 25 | CWE-506 |  |
| H099 | Source Host Swapped Under A Kept Local Name | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H100 | Install Hook Added Or Retargeted | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H101 | Source Pinning Lost | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H102 | Maintainer Change With Signing Key Change | composition | L5 | HIGH | 25 | CWE-506 |  |
| H103 | Metadata And Recipe Disagree | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H104 | Placeholder Package | naming-and-dependency | L5 | INFO | 0 | CWE-427 |  |
| H105 | Adopted Source Executed | maintainer-and-metadata | L5 | HIGH | 25 | CWE-290 |  |
| H106 | Registry Or Index Override | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H107 | Credential Store Access With Egress | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H108 | Service Or Cron Enable Command | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| M001 | Claim Contradicted By Structure | meta |  | HIGH | 25 | CWE-693 |  |
| M002 | Weak Signal Across Layers | meta |  | MEDIUM | 15 | CWE-693 |  |
| M003 | Composition Not Owned Elsewhere | meta |  | MEDIUM | 15 | CWE-693 |  |
| M004 | Expected Co-fire Absent | meta |  | INFO | 0 | CWE-693 |  |
| M005 | Licensor Absent On Licensed Shape | meta |  | INFO | 0 | CWE-693 |  |
| M006 | Campaign Re-armed Too Often | meta |  | INFO | 0 | CWE-693 |  |
| R001 | Remote Script Execution | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R002 | Wget Pipe to Shell | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R003 | Base64 Decode and Execute | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R007 | Install File Modification | install-and-persist | L3 | MEDIUM | 15 | CWE-506 |  |
| R008 | Unexpected File Download | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R010 | Uses curl in PKGBUILD | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R011 | Uses wget in PKGBUILD | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R012 | LLM Prompt Injection | deception | L3 | FATAL | 0 | CWE-506 |  |
| R013 | Unicode Bidi Override | deception | L3 | FATAL | 0 | CWE-506 |  |
| R017 | Setuid/Setgid Permission | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R039 | Eval With Dynamic Content | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R040 | Shell -c With Dynamic Payload | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R041 | Shell Network Redirection | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R042 | Download Then Execute | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R043 | Base64 Blob Decode | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R044 | Interpreter One-Liner With Network | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R045 | Binary Encoding Pipe | obfuscation | L3 | MEDIUM | 15 | CWE-506 |  |
| R046 | Source URL Uses IP Address | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| R047 | Source URL Uses Non-Standard Port | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R048 | Source URL On Free Registrar TLD | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R049 | Compiler Plugin Or Loader Override | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R050 | Compiler Hardening Disabled | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R051 | Network Access In pkgver | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R052 | Dotfile Written To User Profile | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R053 | Setuid Or Setgid Bit Set In Package Root | install-and-persist | L3 | MEDIUM | 15 | CWE-506 |  |
| R054 | Persistence Unit Outside Package Root | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R055 | Git Clone With Variable Branch | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| R056 | Download Then Source | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R057 | TLS Verification Disabled | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R058 | Write Outside Package Root | staging-and-recon | L3 | HIGH | 25 | CWE-506 |  |
| R059 | Setuid Or Setgid Bit Set Outside Package Root | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R078 | Compression Command Override | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R091 | Privilege Escalation Override | integrity | L3 | HIGH | 25 | CWE-354 |  |
| R099 | Trap Statement | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R104 | Error Handling Suppressed | integrity | L3 | HIGH | 25 | CWE-354 |  |
| R144 | Packaged File Points At A World-Writable Path | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R152 | Source URL On Free-Hosting Or Dynamic-DNS Host | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| S001 | Recursive Self-Spawn | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S002 | Recursive Deletion Outside The Build Tree | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S003 | Raw Block Device Write | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S004 | Secure Deletion Of User Data | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S005 | Permission Change On A System Path | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S006 | System Service Disruption | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S007 | Cryptocurrency Miner | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S008 | Shell History Or Log Destruction | sabotage | L3 | MEDIUM | 15 | CWE-506 |  |
| T001 | Signing-Key Novelty | temporal | L6 | HIGH | 25 | CWE-494 |  |
| T002 | Maintainer Domain Novelty | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| T003 | Signing Key Rotated | temporal | L6 | HIGH | 25 | CWE-494 |  |
| T004 | Vouch Surface Removed | temporal | L1 | MEDIUM | 15 | CWE-347 |  |
| T005 | Scheme Downgrade | temporal | L1 | MEDIUM | 15 | CWE-506 |  |
| T006 | Metadata-Git Divergence | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| T007 | Packager Not In History | temporal | L6 | INFO | 0 | CWE-506 |  |
| T008 | Delayed Payload Adoption | temporal | L6 | INFO | 0 | CWE-506 |  |
| T009 | High-Value Dormant Takeover | temporal | L6 | INFO | 0 | CWE-506 |  |
| T010 | Dependency Redirection | naming-and-dependency | L6 | INFO | 0 | CWE-427 |  |
| T011 | Package Reappearance | temporal | L6 | INFO | 0 | CWE-506 |  |
| T012 | Trust Erosion Sequence | temporal | L6 | INFO | 0 | CWE-506 |  |
| U001 | Manifest Added Or Removed | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U002 | Upstream Dependency Delta | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U003 | New Remote Source In Manifest | upstream-manifests | L3 | MEDIUM | 15 | CWE-494 |  |
| U004 | Registry Redirect | upstream-manifests | L3 | MEDIUM | 15 | CWE-494 |  |
| U005 | Dependency Surface Jump | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U006 | Manifest Changed Without Its Lockfile | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U007 | CI Exfil Shape | upstream-release | L7 | MEDIUM | 15 | CWE-200 |  |
| U008 | Git-History Credential Sweep | upstream-release | L7 | MEDIUM | 15 | CWE-522 |  |
| U009 | New CI Surface Committed | upstream-release | L1 | LOW | 5 | CWE-494 |  |
| U010 | Unauditable Upstream | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U011 | Upstream Origin Changed | upstream-manifests | L3 | None | 0 | CWE-494 |  |
| U012 | Lockfile Integrity Weakened | upstream-manifests | L3 | None | 0 | CWE-494 |  |
| U013 | CI Exfil Shape (Local) | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U014 | Git-History Credential Sweep (Local) | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U015 | Federated Upstream Manifest Delta | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| W001 | Executes Code This Analysis Did Not Read | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W002 | Build Resolves Dependencies From A Registry | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W003 | Applies A Patch This Analysis Did Not Read | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W004 | Build Engine Runs A Manifest This Analysis Did Not Read | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W005 | Build Runs A Target Whose Recipe Was Not Read | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W006 | Generated File Names A Build-Only Path | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W007 | Dependency Novelty Declined For Insufficient Observations | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W008 | Unresolved Construct In A Recipe | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W009 | Upstream Manifests Not Examined | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W010 | Alert Volume Capped | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W011 | Upstream Content Not Read | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W012 | Federation Not Consulted | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W013 | Campaign Perimeter Boundary Note | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| W014 | Upstream Scan Not Completed | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| W015 | Archive Structure Ambiguous | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| X001 | Encoded Payload Decoded And Executed | crossfire | L4 | None | 0 | CWE-506 |  |
| X002 | Non-Literal Executable Name | crossfire | L4 | None | 0 | CWE-506 |  |
| X003 | Obfuscated Command Argument | crossfire | L4 | None | 0 | CWE-506 |  |
| X004 | Build Output Suppressed | crossfire | L4 | None | 0 | CWE-506 |  |
| X005 | Home Reached By An Alternative Spelling | crossfire | L4 | None | 0 | CWE-506 |  |
| X006 | Source Points Somewhere Unexpected | crossfire | L4 | None | 0 | CWE-506 |  |
| X007 | Multiple Evasion Techniques | crossfire | L4 | None | 0 | CWE-506 |  |
| X008 | Whitespace A Shell Does Not Split On | crossfire | L4 | None | 0 | CWE-506 |  |
| X009 | Fetch Through An Uncatalogued Client | crossfire | L4 | None | 0 | CWE-506 |  |
| X010 | Interpreter One-Liner Reaches The Network | crossfire | L4 | None | 0 | CWE-506 |  |
| X011 | Package Manager Runs Fetched Code At Build Time | crossfire | L4 | None | 0 | CWE-506 |  |
| X012 | Build Toolchain Redirected Into The Source Tree | crossfire | L4 | None | 0 | CWE-506 |  |
| X013 | Fetch Redirected Or Trust Root Replaced | crossfire | L4 | None | 0 | CWE-506 |  |
| X014 | Environment Variable Names Code To Run | crossfire | L4 | None | 0 | CWE-506 |  |
| X015 | Work Scheduled To Run After The Build | crossfire | L4 | None | 0 | CWE-506 |  |
| X016 | Fetch Piped Into An Unrecognised Consumer | crossfire | L4 | None | 0 | CWE-506 |  |
| X017 | Tool Flag Or Builtin Carries A Command | crossfire | L4 | None | 0 | CWE-506 |  |
| X018 | Interpreter One-Liner Assembles A Name | crossfire | L4 | None | 0 | CWE-506 |  |
| X019 | Host Material Sent Or Packaged | crossfire | L4 | None | 0 | CWE-506 |  |
| X020 | Recipe Writes The Build Steps The Engine Runs | crossfire | L4 | None | 0 | CWE-506 |  |
| X021 | Executor Runs A File Chosen At Runtime | crossfire | L4 | None | 0 | CWE-506 |  |
| X022 | Generated Config Handed To The Tool That Reads It | crossfire | L4 | None | 0 | CWE-506 |  |
| X023 | Command Output Executed As A Script | crossfire | L4 | None | 0 | CWE-506 |  |
| X024 | Indirect Sensitive Assignment | crossfire | L4 | None | 0 | CWE-506 |  |
| X025 | Multi-Line Function Shadow | crossfire | L4 | None | 0 | CWE-506 |  |
| X026 | Unresolved Constructs In Executable Positions | crossfire | L2 | None | 0 | CWE-506 |  |
| X027 | Refusal Cluster | crossfire | L2 | None | 0 | CWE-506 |  |
| X028 | Pattern Completed Across Commits | crossfire | L4 | None | 0 | CWE-506 |  |
| X029 | Encoded Material At Rest | crossfire | L4 | None | 0 | CWE-506 |  |
| X030 | ANSI-C Quoted Content In Commands | crossfire | L4 | None | 0 | CWE-506 |  |
| X031 | Build Reads Non-Code Text | crossfire | L4 | None | 0 | CWE-506 |  |
| X032 | Command Name Assembled By Splicing | crossfire | L4 | None | 0 | CWE-506 |  |
| X033 | File With No Provenance Executed | crossfire | L4 | None | 0 | CWE-506 |  |
| X034 | Fetch Laundered Through An Archival Service | crossfire | L4 | None | 0 | CWE-506 |  |
