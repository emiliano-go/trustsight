<!-- description: Generated coverage map: every shipped rule, its layer, claim category, CWE, weight state and known gap. -->
<!-- generated: threat-coverage -->

# Threat coverage

This page is generated from the shipped registry by
`scripts/build_threat_coverage.py`. It is a map of what the rules claim, not a
claim of complete coverage.

| Rule | Name | Vector | Stage | Category | Layer | Severity | Weight | CWE | Boundary |
|---|---|---|---|---|---|---|---|---|---|
| A001 | Setuid File In Artifact | artifact |  | artifact |  | HIGH | 25 | CWE-250 |  |
| A002 | Undeclared Unit In Artifact | artifact |  | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A003 | Library Outside Depends | artifact |  | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A004 | Install Hook Diverges From Declaration | artifact |  | artifact |  | HIGH | 25 | CWE-506 |  |
| A005 | Unusual Artifact Mode | artifact |  | artifact |  | INFO | 0 | CWE-506 |  |
| A006 | File Capabilities In Artifact | artifact |  | artifact |  | HIGH | 25 | CWE-250 |  |
| A007 | Privileged Surface In Artifact | artifact |  | artifact |  | MEDIUM | 15 | CWE-506 |  |
| A008 | eBPF Artifact In Package | artifact |  | artifact |  | HIGH | 25 | CWE-506 |  |
| A009 | Executable Binary In Source Archive | artifact |  | artifact |  | HIGH | 25 | CWE-506 |  |
| A010 | Setuid File In Source Archive | artifact |  | artifact |  | HIGH | 25 | CWE-250 |  |
| A011 | Hook Runs On Every Transaction | artifact |  | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| A012 | Shipped Hook Or Udev Fetches Or Runs A User Path | artifact |  | artifact |  | HIGH | 0 (anergic) | CWE-506 | calibration |
| A013 | Udev Rule Runs A Program | artifact |  | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| A014 | Unsafe ELF Runpath | artifact |  | artifact |  | HIGH | 0 (anergic) | CWE-506 | calibration |
| A015 | Packed Or Encrypted ELF Section | artifact |  | artifact |  | MEDIUM | 0 (anergic) | CWE-506 | calibration |
| A016 | Release Asset Diverges From Its Tag | artifact |  | artifact |  | HIGH | 0 (anergic) | CWE-506 | calibration |
| C001 | Checksum Changed Without Source Change With Stable Version |  |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C002 | Checksum Updated With Version Bump |  |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C003 | Source URL Changed Without Version Bump |  |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C004 | Checksum Removed For Unchanged Source |  |  | integrity | L1 | CRITICAL | 40 | CWE-354 |  |
| C005 | Binary Artifact From Untrusted Source |  |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C006 | Maintainer Change With New Source Domain |  |  | maintainer-and-metadata | L1 | HIGH | 25 | CWE-290 |  |
| C007 | Command Substitution In Source Array |  |  | fetch-and-execution | L1 | CRITICAL | 40 | CWE-94 |  |
| C008 | Unread Content Moved Under A Stable Version |  |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C009 | Unread Content Moved With The Version |  |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C010 | Binary Metadata File |  |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C011 | Prebuilt Binary From Non-Upstream Host | source |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C012 | Source Domain Resembles Declared Upstream | deception |  | deception | L1 | MEDIUM | 15 | CWE-506 |  |
| C013 | Source Fork Diverges From Declared Upstream | source |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C014 | Array Order Manipulation | integrity |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C015 | Fetch In package() | network |  | fetch-and-execution | L1 | HIGH | 25 | CWE-94 |  |
| C016 | Interpreter Invocation In Install Hook | execution |  | fetch-and-execution | L1 | HIGH | 25 | CWE-94 |  |
| C017 | Install Hook Writes To A User-Writable Location | persistence |  | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C018 | Executable File Committed | integrity |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C019 | File Renamed | integrity |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C020 | Credentials In A Source URL | source |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| C021 | Dependency Removal During A Build Change | composition |  | composition | L1 | HIGH | 25 | CWE-506 |  |
| C022 | Checksum Strength Downgraded | integrity |  | integrity | L1 | HIGH | 25 | CWE-328 |  |
| C023 | IP-Literal Source Host | source |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C024 | Install Script Not Declared | composition |  | composition | L1 | MEDIUM | 15 | CWE-506 |  |
| C025 | Hardening Option Disabled | build |  | staging-and-recon | L1 | LOW | 5 | CWE-506 |  |
| C026 | Empty File Added | integrity |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C027 | Declared Install Script Is Absent | integrity |  | integrity | L1 | INFO | 0 | CWE-354 |  |
| C028 | Build Cache Outside The Build Trees |  |  | staging-and-recon | L1 | None | 0 | CWE-506 |  |
| C029 | Backup Array Gains Entries | persistence |  | install-and-persist | L1 | INFO | 0 | CWE-506 |  |
| C030 | Epoch Removed With Version Unchanged | version |  | maintainer-and-metadata | L1 | INFO | 0 | CWE-290 |  |
| C031 | Boot Or System Image Tool Run During Build | persistence |  | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C032 | Scriptlet Executes Commands At Top Level | install-and-persist | write_then_exec | install-and-persist | L1 | HIGH | 25 | CWE-506 |  |
| C033 | Context Bleed | integrity |  | integrity | L1 | MEDIUM | 15 | CWE-354 |  |
| C034 | Metadata Inconsistency | maintainer-and-metadata |  | maintainer-and-metadata | L1 | INFO | 0 | CWE-290 |  |
| C035 | Owned Namespace Occupied | integrity | takeover | integrity | L1 | HIGH | 0 (anergic) | CWE-354 | calibration |
| D001 | Novel Dependency Added | dependency |  | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| D002 | Typosquatted Dependency | dependency |  | naming-and-dependency | L6 | HIGH | 25 | CWE-427 |  |
| D003 | New Network-Using Makedepends | dependency |  | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| D004 | Dependency Hijack Via Provides | dependency |  | naming-and-dependency | L6 | HIGH | 25 | CWE-427 |  |
| D005 | Official-Repo Name Shadow | dependency |  | naming-and-dependency | L6 | MEDIUM | 15 | CWE-427 |  |
| E001 | Added-Text Compression Ratio | entropy |  | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| E002 | Encoded-Alphabet Fraction | entropy |  | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| E003 | Identifier Entropy | entropy |  | entropy | L4 | MEDIUM | 15 | CWE-506 |  |
| G001 | Shared Gained Host | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G002 | Shared Added Literal | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G003 | Coordinated Adoption | correlation |  | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| G004 | Shared Upstream Dependency | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G005 | Impersonation Campaign | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G006 | Neighborhood Under Campaign Alert | correlation |  | correlation | L8 | INFO | 0 | CWE-506 |  |
| G007 | Campaign Corroboration | correlation |  | correlation | L8 | INFO | 0 | CWE-506 |  |
| G008 | First-Seen Account Adoption Burst | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G009 | Watchlisted Subject | correlation |  | correlation | L8 | INFO | 0 | CWE-506 |  |
| G010 | Shared First-Seen Host | correlation |  | correlation | L8 | INFO | 0 | CWE-506 |  |
| G011 | Maintainer Package Creation Burst | correlation |  | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| G012 | Shared Payload Signal | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G013 | Shared Fetch Target | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G014 | Shared Adoption Window | correlation |  | correlation | L8 | HIGH | 25 | CWE-506 |  |
| G015 | Sleeper Adoption Campaign | correlation |  | correlation | L8 | MEDIUM | 15 | CWE-506 |  |
| G016 | Account Blast Radius | correlation |  | correlation | L8 | INFO | 0 (anergic) | CWE-506 | calibration |
| H001 | Checksum Disabled | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H002 | Checksum Emptied | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H003 | Insecure Download Protocol | integrity |  | fetch-and-execution | L5 | LOW | 5 | CWE-94 |  |
| H004 | Privilege Escalation | privilege |  | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H005 | validpgpkeys Added |  |  | integrity | L5 | None | 0 | CWE-354 |  |
| H006 | New Make/Opt/Check Dependency |  |  | naming-and-dependency | L5 | None | 0 | CWE-427 |  |
| H007 | Symlink Redirect |  |  | staging-and-recon | L5 | None | 0 | CWE-506 |  |
| H008 | Suspicious Environment Variable |  |  | integrity | L5 | None | 0 | CWE-354 |  |
| H009 | Network connection attempt |  |  | fetch-and-execution | L5 | None | 0 | CWE-94 |  |
| H010 | Suspicious file write |  |  | staging-and-recon | L5 | None | 0 | CWE-506 |  |
| H011 | Sensitive binary execution |  |  | fetch-and-execution | L5 | None | 0 | CWE-94 |  |
| H012 | Strace detection attempt (TracerPid check) |  |  | deception | L5 | None | 0 | CWE-506 |  |
| H013 | Strace log truncated (possible flood evasion) |  |  | deception | L5 | None | 0 | CWE-506 |  |
| H014 | Eval or Exec Usage |  |  | obfuscation | L5 | None | 0 | CWE-506 |  |
| H015 | Critical Build Function Modified | build |  | fetch-and-execution | L5 | INFO | 0 | CWE-94 |  |
| H016 | Hidden Network Fetch In Build | network |  | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H017 | Install Hook Fetches Or Executes | installer | install_hook | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H018 | Patch Applied From Outside The Build Tree | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H019 | Source URL Downgraded To HTTP | network |  | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H020 | Very Recent Update | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| H021 | Brand New Package | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| H022 | Stale Package Revived | temporal |  | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| H023 | Install Hook Present | context | install_hook | install-and-persist | L5 | INFO | 0 | CWE-506 |  |
| H024 | GPG Verification Removed | integrity |  | integrity | L5 | HIGH | 25 | CWE-347 |  |
| H025 | Build Environment Subversion | build |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H026 | New Maintainer Without Prior History | maintainer | takeover | maintainer-and-metadata | L6 | HIGH | 25 | CWE-290 |  |
| H027 | Capability Density Anomaly | meta |  | composition | L5 | INFO | 0 | CWE-506 |  |
| H028 | Accelerated Release Cadence |  |  | corpus-behavioral | L6 | None | 0 | CWE-506 |  |
| H029 | Package-Name Typosquat | naming |  | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H030 | Dependency-Set Expansion | dependency |  | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H031 | Version-In-URL Injection | network |  | fetch-and-execution | L5 | MEDIUM | 15 | CWE-94 |  |
| H032 | Write To User Home Or RC | persistence |  | install-and-persist | L5 | CRITICAL | 40 | CWE-506 |  |
| H033 | Moved Git Ref | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H034 | Exotic Source Protocol | network | foreign_fetch | fetch-and-execution | L5 | MEDIUM | 15 | CWE-94 |  |
| H035 | Foreign Package Manager In Install Hook | installer | foreign_fetch | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H036 | Shell Obfuscation Density | obfuscation | obfuscation | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H037 | Long-Stable Property Changed | temporal |  | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H038 | World-Writable Staging | persistence | staging | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H039 | Systemd ExecStart From Runtime-Writable Path | persistence | persistence | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H040 | Host Reconnaissance | recon | recon | staging-and-recon | L5 | INFO | 0 | CWE-506 |  |
| H041 | Upload To Paste Or File-Drop Host | exfil | exfil | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H042 | Hidden Drop | persistence | hidden_drop | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H043 | Attack-Chain Composition | meta |  | composition | L5 | INFO | 0 | CWE-506 |  |
| H044 | Ownership Transition | maintainer | takeover | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H045 | Mass Adoption | adoption | mass_adoption | count-based | L6 | HIGH | 25 | CWE-506 |  |
| H046 | Orphan/Adoption Dependency | dependency |  | corpus-behavioral | L6 | MEDIUM | 15 | CWE-506 |  |
| H047 | Security-Relevant Build Flag Change | build |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H048 | Dependency Vendored Into Source | dependency |  | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H049 | Source Origin Changed | source |  | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H050 | Version Scheme Changed | context |  | maintainer-and-metadata | L5 | INFO | 0 | CWE-290 |  |
| H051 | Package Description Changed | integrity |  | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H052 | Shared Source Repository | adoption |  | count-based | L5 | HIGH | 25 | CWE-506 |  |
| H053 | Name/Host Consensus Divergence | source |  | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H054 | Build System Changed | build |  | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H055 | Attribute Burst | adoption |  | count-based | L5 | MEDIUM | 15 | CWE-506 |  |
| H056 | Known Indicator of Compromise | ioc |  | indicator | L7 | FATAL | 0 | CWE-506 |  |
| H057 | Transitive Exposure | dependency |  | corpus-behavioral | L5 | INFO | 0 | CWE-506 |  |
| H058 | Maintainer Baseline Deviation | adoption |  | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H059 | Name/Repo Divergence | source |  | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H060 | Transitive Orphan Risk | dependency |  | corpus-behavioral | L6 | INFO | 0 | CWE-506 |  |
| H061 | Dependency Centrality | dependency |  | corpus-behavioral | L5 | INFO | 0 | CWE-506 |  |
| H062 | Pacman Hook Installed | persistence | persistence | install-and-persist | L5 | MEDIUM | 15 | CWE-506 |  |
| H063 | Epoch Introduced | version |  | maintainer-and-metadata | L5 | MEDIUM | 15 | CWE-290 |  |
| H064 | Provides/Replaces Scope Expansion | dependency |  | naming-and-dependency | L5 | HIGH | 25 | CWE-427 |  |
| H065 | Obfuscated Literal Reconstructed | obfuscation | obfuscation | obfuscation | L5 | INFO | 0 | CWE-506 |  |
| H066 | Embedded Binary In Tree | integrity | foreign_fetch | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H067 | Anti-Analysis Check | anti_analysis | anti_analysis | deception | L5 | HIGH | 25 | CWE-506 |  |
| H068 | Reconstructed Executable Payload | execution | payload | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H069 | Build-time Generation Then Execution | execution | payload | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H070 | Archive Trailer Anomaly | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H071 | Covert Egress | network | exfil | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H072 | Write Then Execute | execution | write_then_exec | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H073 | Introduction Rate Deviation | adoption | mass_adoption | corpus-behavioral | L6 | MEDIUM | 15 | CWE-506 |  |
| H074 | Adopt-then-Modify | maintainer | takeover | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H075 | Remote Script Via Process Substitution | execution | foreign_fetch | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H076 | Build Writes Outside Staging Root | persistence | persistence | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H077 | Parse-time Network Fetch | network |  | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H078 | Signing Key Set Changed | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H079 | Build Flags Weakened | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H080 | Indirect Command Expansion | obfuscation | anti_analysis | obfuscation | L5 | CRITICAL | 40 | CWE-506 |  |
| H081 | Committed File Executed Without Declaration | execution | write_then_exec | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H082 | Fetch Then Execute | network_execution | write_then_exec | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H083 | Downloaded Source File Executed | execution | write_then_exec | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H084 | Service ExecStart Targets Undeclared Binary | persistence |  | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H085 | PATH Injection With Undeclared Directory | build |  | staging-and-recon | L5 | HIGH | 25 | CWE-506 |  |
| H086 | Adopted From Orphan | maintainer | takeover | maintainer-and-metadata | L6 | MEDIUM | 15 | CWE-290 |  |
| H087 | Recipe Changed Without Upstream | integrity | integrity_removed | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H088 | Adopted, Recipe Rewritten, Unpinned Fetch | takeover | takeover | maintainer-and-metadata | L6 | HIGH | 25 | CWE-290 |  |
| H089 | Packaged File Names A Build-Only Path | persistence | persistence | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H090 | Committed Companion Carries A Fetch-Execute Payload | delivery | foreign_fetch | fetch-and-execution | L5 | CRITICAL | 40 | CWE-94 |  |
| H091 | Checksum Array Shorter Than Source Array | integrity | integrity_removed | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H092 | Metadata Names A Source The Recipe Does Not | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H093 | Committed Config Points At A Build-Only Path | persistence | persistence | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H094 | Unread Script Executed During Packaging | execution |  | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H095 | Boot Or Image Artifact Built From The Source Tree | persistence | persistence | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H096 | Download Agent Override | network |  | integrity | L5 | MEDIUM | 15 | CWE-354 |  |
| H097 | Function Shadowing | integrity |  | integrity | L5 | HIGH | 25 | CWE-354 |  |
| H098 | Naming/Deception Cluster | meta |  | composition | L5 | HIGH | 25 | CWE-506 |  |
| H099 | Source Host Swapped Under A Kept Local Name | integrity |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H100 | Install Hook Added Or Retargeted | install-and-persist | install_hook | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H101 | Source Pinning Lost | integrity |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H102 | Maintainer Change With Signing Key Change | meta |  | composition | L5 | HIGH | 25 | CWE-506 |  |
| H103 | Metadata And Recipe Disagree | integrity |  | integrity | L1 | HIGH | 25 | CWE-354 |  |
| H104 | Placeholder Package | naming |  | naming-and-dependency | L5 | INFO | 0 | CWE-427 |  |
| H105 | Adopted Source Executed | maintainer | takeover | maintainer-and-metadata | L5 | HIGH | 25 | CWE-290 |  |
| H106 | Registry Or Index Override | dependency | registry | naming-and-dependency | L5 | MEDIUM | 15 | CWE-427 |  |
| H107 | Credential Store Access With Egress | exfil | exfil | fetch-and-execution | L5 | HIGH | 25 | CWE-94 |  |
| H108 | Service Or Cron Enable Command | persistence | persistence | install-and-persist | L5 | HIGH | 25 | CWE-506 |  |
| H109 | Build Helper Executed From A Secondary Source | execution |  | fetch-and-execution | L5 | HIGH | 0 (anergic) | CWE-94 | calibration |
| M001 | Claim Contradicted By Structure | meta |  | meta |  | HIGH | 25 | CWE-693 |  |
| M002 | Weak Signal Across Layers | meta |  | meta |  | MEDIUM | 15 | CWE-693 |  |
| M003 | Composition Not Owned Elsewhere | meta |  | meta |  | MEDIUM | 15 | CWE-693 |  |
| M004 | Expected Co-fire Absent | meta |  | meta |  | INFO | 0 | CWE-693 |  |
| M005 | Licensor Absent On Licensed Shape | meta |  | meta |  | INFO | 0 | CWE-693 |  |
| M006 | Campaign Re-armed Too Often | meta |  | meta |  | INFO | 0 | CWE-693 |  |
| R001 | Remote Script Execution | network_execution | foreign_fetch | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R002 | Wget Pipe to Shell | network_execution |  | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R003 | Base64 Decode and Execute | obfuscation |  | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R007 | Install File Modification | installer |  | install-and-persist | L3 | MEDIUM | 15 | CWE-506 |  |
| R008 | Unexpected File Download | network_execution |  | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R010 | Uses curl in PKGBUILD | network_usage |  | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R011 | Uses wget in PKGBUILD | network_usage |  | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R012 | LLM Prompt Injection | injection |  | deception | L3 | FATAL | 0 | CWE-506 |  |
| R013 | Unicode Bidi Override | unicode |  | deception | L3 | FATAL | 0 | CWE-506 |  |
| R017 | Setuid/Setgid Permission | privilege |  | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R039 | Eval With Dynamic Content | execution |  | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R040 | Shell -c With Dynamic Payload | execution |  | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R041 | Shell Network Redirection | network_execution | foreign_fetch | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R042 | Download Then Execute | execution |  | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R043 | Base64 Blob Decode | obfuscation |  | obfuscation | L3 | CRITICAL | 40 | CWE-506 |  |
| R044 | Interpreter One-Liner With Network | network_execution |  | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R045 | Binary Encoding Pipe | obfuscation |  | obfuscation | L3 | MEDIUM | 15 | CWE-506 |  |
| R046 | Source URL Uses IP Address | network |  | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| R047 | Source URL Uses Non-Standard Port | network |  | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R048 | Source URL On Free Registrar TLD | network |  | fetch-and-execution | L3 | LOW | 5 | CWE-94 |  |
| R049 | Compiler Plugin Or Loader Override | build |  | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R050 | Compiler Hardening Disabled | build |  | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R051 | Network Access In pkgver | packaging |  | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R052 | Dotfile Written To User Profile | persistence |  | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R053 | Setuid Or Setgid Bit Set In Package Root | privilege |  | install-and-persist | L3 | MEDIUM | 15 | CWE-506 |  |
| R054 | Persistence Unit Outside Package Root | persistence | persistence | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R055 | Git Clone With Variable Branch | source |  | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| R056 | Download Then Source | execution |  | fetch-and-execution | L3 | CRITICAL | 40 | CWE-94 |  |
| R057 | TLS Verification Disabled | network |  | fetch-and-execution | L3 | HIGH | 25 | CWE-94 |  |
| R058 | Write Outside Package Root | system |  | staging-and-recon | L3 | HIGH | 25 | CWE-506 |  |
| R059 | Setuid Or Setgid Bit Set Outside Package Root | privilege |  | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R078 | Compression Command Override | build |  | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R091 | Privilege Escalation Override | build |  | integrity | L3 | HIGH | 25 | CWE-354 |  |
| R099 | Trap Statement | build |  | integrity | L3 | MEDIUM | 15 | CWE-354 |  |
| R104 | Error Handling Suppressed | build |  | integrity | L3 | HIGH | 25 | CWE-354 |  |
| R144 | Packaged File Points At A World-Writable Path | persistence | persistence | install-and-persist | L3 | HIGH | 25 | CWE-506 |  |
| R152 | Source URL On Free-Hosting Or Dynamic-DNS Host | network |  | fetch-and-execution | L3 | MEDIUM | 15 | CWE-94 |  |
| S001 | Recursive Self-Spawn | sabotage | sabotage | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S002 | Recursive Deletion Outside The Build Tree | sabotage | sabotage | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S003 | Raw Block Device Write | sabotage | sabotage | sabotage | L3 | CRITICAL | 40 | CWE-506 |  |
| S004 | Secure Deletion Of User Data | sabotage | sabotage | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S005 | Permission Change On A System Path | sabotage | sabotage | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S006 | System Service Disruption | sabotage | sabotage | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S007 | Cryptocurrency Miner | sabotage | sabotage | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S008 | Shell History Or Log Destruction | sabotage | anti_analysis | sabotage | L3 | MEDIUM | 15 | CWE-506 |  |
| S009 | Privileged Account Or udev Rule | sabotage |  | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| S010 | Kernel Module Loaded During Build | sabotage |  | sabotage | L3 | HIGH | 25 | CWE-506 |  |
| T001 | Signing-Key Novelty | temporal |  | temporal | L6 | HIGH | 25 | CWE-494 |  |
| T002 | Maintainer Domain Novelty | temporal |  | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| T003 | Signing Key Rotated | temporal |  | temporal | L6 | HIGH | 25 | CWE-494 |  |
| T004 | Vouch Surface Removed | temporal |  | temporal | L1 | MEDIUM | 15 | CWE-347 |  |
| T005 | Scheme Downgrade | temporal |  | temporal | L1 | MEDIUM | 15 | CWE-506 |  |
| T006 | Metadata-Git Divergence | temporal |  | temporal | L6 | MEDIUM | 15 | CWE-506 |  |
| T007 | Packager Not In History | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| T008 | Delayed Payload Adoption | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| T009 | High-Value Dormant Takeover | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| T010 | Dependency Redirection | dependency |  | naming-and-dependency | L6 | INFO | 0 | CWE-427 |  |
| T011 | Package Reappearance | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| T012 | Trust Erosion Sequence | temporal |  | temporal | L6 | INFO | 0 | CWE-506 |  |
| U001 | Manifest Added Or Removed | dependency-manifest |  | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U002 | Upstream Dependency Delta | dependency-manifest |  | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U003 | New Remote Source In Manifest | dependency-manifest |  | upstream-manifests | L3 | MEDIUM | 15 | CWE-494 |  |
| U004 | Registry Redirect | dependency-manifest |  | upstream-manifests | L3 | MEDIUM | 15 | CWE-494 |  |
| U005 | Dependency Surface Jump | dependency-manifest |  | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U006 | Manifest Changed Without Its Lockfile | dependency-manifest |  | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| U007 | CI Exfil Shape | upstream-ci |  | upstream-release | L7 | MEDIUM | 15 | CWE-200 |  |
| U008 | Git-History Credential Sweep | upstream-ci |  | upstream-release | L7 | MEDIUM | 15 | CWE-522 |  |
| U009 | New CI Surface Committed | upstream-ci |  | upstream-release | L1 | LOW | 5 | CWE-494 |  |
| U010 | Unauditable Upstream | source |  | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U011 | Upstream Origin Changed |  |  | upstream-manifests | L3 | None | 0 | CWE-494 |  |
| U012 | Lockfile Integrity Weakened |  |  | upstream-manifests | L3 | None | 0 | CWE-494 |  |
| U013 | CI Exfil Shape (Local) | upstream-ci |  | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U014 | Git-History Credential Sweep (Local) | upstream-ci |  | upstream-release | L3 | MEDIUM | 15 | CWE-494 |  |
| U015 | Federated Upstream Manifest Delta | dependency-manifest |  | upstream-manifests | L3 | INFO | 0 | CWE-494 |  |
| W001 | Executes Code This Analysis Did Not Read |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W002 | Build Resolves Dependencies From A Registry |  | registry | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W003 | Applies A Patch This Analysis Did Not Read |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W004 | Build Engine Runs A Manifest This Analysis Did Not Read |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W005 | Build Runs A Target Whose Recipe Was Not Read |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W006 | Generated File Names A Build-Only Path |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W007 | Dependency Novelty Declined For Insufficient Observations |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W008 | Unresolved Construct In A Recipe |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W009 | Upstream Manifests Not Examined |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W010 | Alert Volume Capped |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W011 | Upstream Content Not Read |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W012 | Federation Not Consulted |  |  | unverifiable | L2 | None | 0 | CWE-693 | boundary |
| W013 | Campaign Perimeter Boundary Note | unverifiable |  | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| W014 | Upstream Scan Not Completed | unverifiable |  | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| W015 | Archive Structure Ambiguous | unverifiable |  | unverifiable | L2 | INFO | 0 | CWE-693 | boundary |
| X001 | Encoded Payload Decoded And Executed |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X002 | Non-Literal Executable Name |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X003 | Obfuscated Command Argument |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X004 | Build Output Suppressed |  | anti_analysis | crossfire | L4 | None | 0 | CWE-506 |  |
| X005 | Home Reached By An Alternative Spelling |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X006 | Source Points Somewhere Unexpected |  | foreign_fetch | crossfire | L4 | None | 0 | CWE-506 |  |
| X007 | Multiple Evasion Techniques |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X008 | Whitespace A Shell Does Not Split On |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X009 | Fetch Through An Uncatalogued Client |  | foreign_fetch | crossfire | L4 | None | 0 | CWE-506 |  |
| X010 | Interpreter One-Liner Reaches The Network |  | foreign_fetch | crossfire | L4 | None | 0 | CWE-506 |  |
| X011 | Package Manager Runs Fetched Code At Build Time |  | payload | crossfire | L4 | None | 0 | CWE-506 |  |
| X012 | Build Toolchain Redirected Into The Source Tree |  | write_then_exec | crossfire | L4 | None | 0 | CWE-506 |  |
| X013 | Fetch Redirected Or Trust Root Replaced |  | foreign_fetch | crossfire | L4 | None | 0 | CWE-506 |  |
| X014 | Environment Variable Names Code To Run |  | write_then_exec | crossfire | L4 | None | 0 | CWE-506 |  |
| X015 | Work Scheduled To Run After The Build |  | persistence | crossfire | L4 | None | 0 | CWE-506 |  |
| X016 | Fetch Piped Into An Unrecognised Consumer |  | foreign_fetch | crossfire | L4 | None | 0 | CWE-506 |  |
| X017 | Tool Flag Or Builtin Carries A Command |  | payload | crossfire | L4 | None | 0 | CWE-506 |  |
| X018 | Interpreter One-Liner Assembles A Name |  | obfuscation | crossfire | L4 | None | 0 | CWE-506 |  |
| X019 | Host Material Sent Or Packaged |  | exfil | crossfire | L4 | None | 0 | CWE-506 |  |
| X020 | Recipe Writes The Build Steps The Engine Runs |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X021 | Executor Runs A File Chosen At Runtime |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X022 | Generated Config Handed To The Tool That Reads It |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X023 | Command Output Executed As A Script |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X024 | Indirect Sensitive Assignment |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X025 | Multi-Line Function Shadow |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X026 | Unresolved Constructs In Executable Positions |  |  | crossfire | L2 | None | 0 | CWE-506 |  |
| X027 | Refusal Cluster |  |  | crossfire | L2 | None | 0 | CWE-506 |  |
| X028 | Pattern Completed Across Commits |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X029 | Encoded Material At Rest |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X030 | ANSI-C Quoted Content In Commands |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X031 | Build Reads Non-Code Text |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X032 | Command Name Assembled By Splicing |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X033 | File With No Provenance Executed |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
| X034 | Fetch Laundered Through An Archival Service |  |  | crossfire | L4 | None | 0 | CWE-506 |  |
