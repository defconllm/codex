# Windows 11 Security Controls Taxonomy

**Windows 11 Security Controls Taxonomy - Harden-Windows11 v2.2 Coverage Map**

Maps recognized endpoint security control domains to what this tool actually implements, whether each control is closed, the residual risk, and the context an assessor needs. Derived from the script's own -Item audit labels and module structure, not from memory.

- **Target:** Windows 11 Home/Pro/Enterprise (Core edition tested, Build 22631)
- **Generated for:** AINetGuard pentest / audit evidence

**Level 2 tier:** Level 2 (lockout-risk) tier: a menu grouping (main menu option 9) of the sharp, lockout-capable lockdowns - RDP+SSH lockdown, block-all-inbound, block-outbound, NTLM-deny. Each runs individually with its own confirmation and remote-session guard, or all as a batch. Deliberately separate from the safe baseline (menu 2) so nothing lockout-risky runs unless explicitly chosen.

## Coverage summary

74 controls across 19 domains.

| status | count | meaning |
|---|---|---|
| closed | 46 | Control is applied in the BASELINE (menu 2 harden) and verified by the tool. |
| opt_in | 21 | Control is available but NOT in the baseline; must be chosen (flag or extra-security menu). Off by default for a reason stated in context. |
| partial | 1 | Control is addressed but not fully - the tool does part of it, or applies it in a weaker/safer form than the strictest benchmark. |
| not_covered | 6 | Out of scope for this tool. Reason stated in context (usually needs AD/Intune/cloud, or is a firmware/physical control, or would brick a standalone box). |

| risk | count |
|---|---|
| critical | 4 |
| high | 31 |
| medium | 32 |
| low | 7 |

> **Caveat:** CIS/STIG control NUMBERS referenced in the script are indicative and were current to the guides reviewed (through ~2026). Benchmark numbering shifts between versions - a compliance owner should cross-check against the exact benchmark version being audited against.

---

## Credential Protection

*MITRE ATT&CK TA0006 (Credential Access), T1003 (OS Credential Dumping)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| WDigest cleartext credential caching disabled | **closed** | critical | 1 | UseLogonCredential=0. The classic mimikatz sekurlsa::wdigest target - with it on, cleartext passwords sit in LSASS. Highest-impact single item; a guaranteed audit finding if missing. |
| LSASS as Protected Process Light (RunAsPPL) | **closed** | critical | 2 | Prevents non-PPL processes (most credential dumpers) from opening LSASS memory. Takes effect after reboot - tool reports PENDING until then. |
| No LM hash stored / anonymous enumeration restricted / null-session lockdown | **closed** | high | 2 | NoLMHash=1, RestrictAnonymous(SAM)=1, EveryoneIncludesAnonymous=0, RestrictNullSessAccess=1, empty NullSessionPipes/Shares. Blocks anonymous SMB enumeration and trivially-crackable LM hashes. |
| LDAP client signing / Kerberos AES-only | **closed** | medium | 2 | LDAPClientIntegrity=1, SupportedEncryptionTypes=AES-only (no RC4/DES). Inert-but-harmless on a standalone box; interacts with DC capabilities on a domain. |
| ROCA-vulnerable WHfB key block (CVE-2017-15361) | **closed** | medium | 2 | Blocks Windows Hello auth using keys from vulnerable Infineon TPMs. Harmless on unaffected TPMs. |
| Cached domain logons limited | **closed** | low | 2 | CachedLogonsCount=4. Fewer offline-crackable cached verifiers. |
| Credential Guard (VBS-isolated LSA) | **opt_in** | high | 3 | Enabled via -IncludeDeviceGuard (LsaCfgFlags). UEFI lock is OFF by default and only set via -CredentialGuardUEFILock - the lock is a documented DoS trap (needs physical presence to disable). Requires reboot + hardware support. |

## Authentication and Account Policy

*MITRE ATT&CK T1110 (Brute Force), T1078 (Valid Accounts)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Password length / complexity / history / max-age | **opt_in** | medium | 2 | OPT-IN (extra security > password policy), NOT baseline - enforcing 14-char/complexity/lockout on a personal or lab box locks you out of your own accounts. Two explicit modes: ENFORCE (CIS values) and RELAX (remove requirements). Applies to LOCAL accounts; domain accounts governed by domain GPO. |
| Account lockout threshold | **opt_in** | medium | 2 | 5-try lockout / 15-min duration. Same opt-in rationale. Deliberately more forgiving than STIG's 3-try to avoid self-inflicted DoS lockouts. |
| PKINIT SHA-1 deprecation (Kerberos cert-auth crypto agility) | **opt_in** | medium | 3 | OPT-IN, domain-guarded. Refuses SHA-1 in smart-card/WHfB Kerberos auth. DANGER: silently breaks auth against pre-Server-2025 DCs (error 0x3bc4) - requires -Force on a domain-joined box, reversible from console. Inert on standalone. |
| Built-in Administrator / Guest account hygiene | **opt_in** | high | 2 | Via -DisableBuiltinAdmin. Guarded to never remove your last admin (requires -VerifiedAdminAccount). LAPS auto-rotation is out of scope (needs AD/Entra). |

## Network Name Resolution and Broadcast Poisoning

*MITRE ATT&CK T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| LLMNR disabled | **closed** | high | 1 | EnableMulticast=0. Responder/Inveigh poison LLMNR (UDP 5355) to capture NTLM hashes. Zero operational impact with healthy DNS. |
| NetBIOS over TCP/IP disabled (registry + per-adapter) | **closed** | high | 2 | EnableNetbios=0 at Dnscache layer plus SetTcpipNetbios(2) per adapter (belt-and-suspenders - the per-adapter GPO is unreliable on static IPs). |
| mDNS disabled | **closed** | medium | 2 | EnableMDNS=0. Removes another broadcast query vector (UDP 5353). Breaks Bonjour/AirPlay/Chromecast discovery. |
| WPAD auto-proxy disabled | **closed** | high | 1 | Blocks Web Proxy Auto-Discovery, a Responder/proxy-poisoning MitM vector. |
| NetBIOS name-release ignore / no insecure guest SMB | **closed** | medium | 2 | NoNameReleaseOnDemand=1, AllowInsecureGuestAuth=0. Stops name-release DoS and silent fallback to unauthenticated guest SMB sessions. |

## SMB and Lateral Movement Paths

*MITRE ATT&CK T1021.002 (SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| SMBv1 removed | **closed** | critical | 2 | EternalBlue/MS17-010 surface. Removed as an optional feature; state-checked first so already-absent doesn't false-fail. |
| SMB signing required (client and server) | **closed** | high | 2 | RequireSecuritySignature=1 on BOTH sides. Defends SMB relay. Signing is NOT encryption - noted honestly; for encryption set EncryptData per-share. |
| SMB server disabled (LanmanServer) | **closed** | high | 3 | Aggressive baseline: the box does not host shares. Deduplicated with the admin-share and RDP controls. |
| SMB client disabled (LanmanWorkstation) | **closed** | high | 4 | Aggressive baseline; -KeepSMBClient opt-out. Breaks \\server shares, mapped drives, and domain GPO/SYSVOL. Operational menu 8 can temporarily re-enable. |
| Admin shares removed (C$, ADMIN$) | **opt_in** | high | 3 | AutoShareWks/AutoShareServer=0 via extra-security > aggressive network. Breaks PsExec, MECM/SCCM push, and credentialed scanners - hence opt-in. |
| UNC path hardening (SYSVOL / NETLOGON) | **opt_in** | medium | 2 | RequireMutualAuthentication+Integrity. Blocks spoofed-DC malicious GPO delivery. Domain-only; inert-but-harmless standalone; breaks if DCs lack SMB signing. |

## NTLM and Legacy Authentication Protocols

*MITRE ATT&CK T1550.002 (Pass the Hash), T1557 (Relay)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| LM/NTLMv1 refused (LmCompatibilityLevel) | **closed** | high | 2 | Configurable via -LmCompatibilityLevel (default hardened). Refuses LM and NTLMv1 responses. |
| Outbound NTLM audit / deny | **opt_in** | high | 3 | Audits inbound NTLM by default; -EnforceNTLMDeny sets RestrictSendingNTLMTraffic=2. Deny breaks IP-based access, non-domain servers, some Wi-Fi 802.1X/VPN RADIUS - audit first. |

## Remote Access and Management Surface

*MITRE ATT&CK T1021.001 (RDP), T1021.006 (WinRM)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| RDP inbound denied | **closed** | high | 2 | fDenyTSConnections=1. Box is not an RDP target. Menu 8 can temporarily allow with auto-relock. |
| RDP clipboard / drive redirection blocked | **closed** | medium | 2 | fDisableClip/fDisableCdm=1. Closes the remote-session exfil channel. |
| WinRM / Remote Assistance / Remote Registry disabled | **closed** | high | 3 | Removes remote PowerShell, unsolicited Remote Assistance, and remote registry reconnaissance. |
| RDP + SSH network remote-shell lockdown (Level 2) | **opt_in** | high | 3 | Level 2 menu option 1 / -LockdownRemoteShell. Dedicated lockout-risk option that closes BOTH interactive network remote-shell paths together: RDP (service + firewall group + fDenyTSConnections) and OpenSSH server (sshd + ssh-agent + inbound firewall rule). Does NOT touch the SSH client (outbound, useful). Refuses over the RDP/WinRM session it would sever without -Force; reversible. Segmented into the Level 2 tier - lockout-capable items runnable individually or as a batch, kept out of the safe baseline. |

## Attack Surface Reduction (ASR) and Exploit Guard

*MITRE ATT&CK T1204 (User Execution), T1059 (Command and Scripting), T1055 (Process Injection)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| ASR rule set (13 Enabled, 2 Audit) | **closed** | high | 2 | LSASS theft, email/webmail exec, Office child-proc/inject/exec-content, obfuscated scripts, Win32-from-macro, ransomware, WMI persistence, BYOVD, USB-unsigned. PSExec/WMI and prevalence/age rules in AUDIT (they break admin/pentest tooling and are FP-prone). |
| Microsoft Vulnerable Driver Blocklist (anti-BYOVD) | **closed** | high | 2 | VulnerableDriverBlocklistEnable=1. Blocks known-exploitable signed ring-0 drivers. Verify re-checks it (adversaries set it to 0). |
| Application allowlisting (WDAC) | **partial** | high | 3 | Generates an AUDIT-mode policy only (-GenerateWDACAuditPolicy). Enforcement needs weeks of telemetry + signed per-app exclusions - a deliberate rollout, not a script toggle. |

## Privilege Escalation and Elevation Control

*MITRE ATT&CK TA0004 (Privilege Escalation), T1548 (Abuse Elevation Control)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| UAC enabled + secure-desktop prompts | **closed** | critical | 1 | EnableLUA=1, PromptOnSecureDesktop=1, admin-consent prompt, installer-detection, RID-500 admin-approval-mode. A disabled UAC is a critical finding. |
| Enhanced Admin Approval Mode (EPP, 24H2) | **closed** | medium | 2 | TypeOfAdminApprovalMode=2. VBS-isolates the elevation token so a keylogger/injector can't hijack it. Inert-but-harmless pre-24H2. |
| MSI never installs elevated (AlwaysInstallElevated=0) | **closed** | high | 2 | Both hives. A classic LPE if left on (=1 lets any user install MSIs as SYSTEM). |
| Unquoted service path detection | **closed** | high | 2 | Read-only gap detection (CWE-428). Flags services whose ImagePath has spaces and no quotes - a reliable LPE vector. Detection only; remediation is manual (quote the path). |
| Orphaned service detection | **closed** | medium | 2 | Read-only. Flags registered services whose binary is missing (an attacker who can write the path hijacks the dormant registration). |
| Windows sudo disabled | **opt_in** | medium | 3 | The new Windows sudo can be an elevation path; disabled via extra-security. |

## Boot and Kernel Integrity

*MITRE ATT&CK T1542 (Pre-OS Boot), T1014 (Rootkit)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| VBS / HVCI (Memory Integrity) | **opt_in** | high | 3 | Via -IncludeDeviceGuard. Hypervisor-isolated kernel-driver validation. Opt-in because it needs hardware support + reboot and can conflict with some virtualization tools. UEFI lock deliberately off by default. |
| WPBT firmware-binary execution disabled | **opt_in** | medium | 3 | Stops attacker firmware pulling code at boot. Via -BlockDeviceAutoInstall. |
| UEFI mode vs Legacy BIOS / Secure Boot / TPM presence | **not_covered** | high | 2 | Firmware/physical controls cannot be set from the OS. Verify manually (STIG V-253256 etc). |

## Data at Rest Encryption

*MITRE ATT&CK T1005 (Data from Local System), physical theft*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| BitLocker XTS-AES-256 with TPM+PIN pre-boot | **opt_in** | high | 2 | Via -EnableBitLocker. Needs a key-escrow path (-BitLockerKeyBackupPath). Pre-boot PIN blocks unattended patch reboots - weigh vs patch cadence. Not baseline because it is near-irreversible and needs escrow. |

## Peripheral and Removable Media Control

*MITRE ATT&CK T1091 (Replication Through Removable Media), T1200 (Hardware Additions)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| AutoRun/AutoPlay disabled all drives | **closed** | high | 1 | NoDriveTypeAutoRun=255, NoAutorun, no MTP/PTP autoplay. Closes the USB auto-execute path. |
| USB device allowlisting (learn present, deny new) | **opt_in** | medium | 3 | Via -USBGuard. Keyboard/mouse force-included so the console can't be bricked. Run at the console. Adopt-new via operational menu. |
| USB mass storage disabled | **opt_in** | medium | 3 | Via -BlockUSBStorage (USBSTOR Start=4). Blocks all USB storage class. |
| No driver/app auto-install on device insert | **opt_in** | medium | 3 | Via -BlockDeviceAutoInstall. Stops new hardware pulling drivers/companion apps from Windows Update on insert. |
| Bluetooth stack disabled | **opt_in** | medium | 3 | Via extra-security. STIG-mandated; breaks BT peripherals (mice/keyboards/headsets). |

## Printing (PrintNightmare)

*MITRE ATT&CK T1068 (Exploitation for Privilege Escalation)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Print Spooler remote RPC endpoint off (local printing kept) | **closed** | high | 2 | Baseline keeps local printing but kills the remote spooler RPC (PrintNightmare surface). Point-and-Print restricted to admins. -KeepPrinting / full-disable options available. |
| Windows Protected Print (WPP, driverless) | **opt_in** | medium | 3 | Via extra-security. Spooler drops to USER context; only IPP/Mopria. WARNING: permanently deletes non-IPP queues + blocks 3rd-party drivers; 24H2+ only. Audit printer fleet first. |

## Network Egress and Firewall

*MITRE ATT&CK TA0011 (Command and Control), T1048 (Exfiltration Over Alternative Protocol)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Defender Firewall on, default-deny inbound, drop logging | **closed** | high | 1 | All profiles on, inbound default-block, dropped-packet logging for C2 hunting. |
| IPv6 transition tech off (Teredo/ISATAP/6to4/IP-HTTPS) | **closed** | medium | 2 | Synthetic tunnels over IPv4 that bypass IPv4 firewall/IDS - a classic exfil corridor. No impact on native v4/v6. |
| IP source routing / ICMP redirects / RPC auth / mobile hotspot | **closed** | medium | 2 | DisableIPSourceRouting(v4+v6), EnableICMPRedirect=0, RestrictRemoteClients=1 (auth-with-exceptions, deliberately not the breaking 2), NC_ShowSharedAccessUI=0. |
| Full outbound default-deny | **opt_in** | high | 4 | Via -BlockOutbound. Needs a per-environment allow-list or it breaks updates/licensing/LOB apps. Does NOT stop exfil over an already-allowed HTTPS channel - stated honestly. |
| DoH require / hardcoded NTP / adapter-binding strips / MAC randomization / local-rule-merge-off | **not_covered** | medium | 4 | Declined: DoHPolicy=3 breaks all DNS if the DoH server is unreachable; hardcoded NTP is env-specific; adapter-binding strips / SMB2-disable break modern file access; local-rule-merge-off needs a GPO backend. |
| Block all inbound (disable every inbound allow rule) | **opt_in** | medium | 3 | Dangerous menu option 'i' / -BlockAllInbound. The baseline already default-blocks inbound, but Windows ships many ENABLED inbound allow rules (Network Discovery, File/Printer Sharing, Cast to Device, mDNS, Remote Assistance, Delivery Optimization inbound) that punch holes through it. This disables all of them so nothing is reachable, preserving only Core Networking (DHCP/IPv6-ND) so the stack still works. Refuses over RDP/WinRM without -Force (would sever the session); reversible via the undo script. Verify now reports the count of non-core inbound allow rules so the exposure is visible either way. |

## Web and Application Reputation

*MITRE ATT&CK T1189 (Drive-by Compromise), T1204 (User Execution)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| SmartScreen (shell + Edge) at Block level | **closed** | medium | 1 | EnableSmartScreen, ShellSmartScreenLevel=Block, Edge SmartScreen + PUA blocking. Removes the user-override bypass. |
| Edge Enhanced Security Mode (JIT off) | **closed** | medium | 2 | EnhanceSecurityMode=2. The 24H2 replacement for the removed Application Guard; disables JIT JS on untrusted sites. |
| Legacy SSL/TLS disabled | **closed** | medium | 2 | Legacy protocol versions off (server/client) and off-by-default. |
| WinINET TLS 1.2/1.3 pinning + cert revocation checking | **closed** | medium | 2 | The WinINET peer to the SCHANNEL protocol work: SecureProtocols=0x2800 (TLS 1.2+1.3 only) on the Internet Settings hive that IE-engine/WinINET HTTP clients use (Edge IE-mode, some .NET/system components), plus CertificateRevocation=1 (CRL/OCSP), warn-on-cert-mismatch, and no-caching-of-HTTPS-pages. Closes a TLS-downgrade path the SCHANNEL layer alone does not cover. HKLM+HKCU. Deliberately did NOT set the poorly-documented WinTrust signature-check bitmask (guessing a crypto-trust value is worse than omitting it). |

## Endpoint Protection (Defender)

*MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Real-time / behavior / PUA / network protection on | **closed** | high | 1 | Baseline turns on the full Defender protection stack. |
| Cloud protection / sample submission OFF by default (no-exfil) | **closed** | low | 1 | DELIBERATE privacy choice: SpyNet/sample submission off by default, which REDUCES cloud-delivered protection. Re-enable with -CloudProtection. This is a tradeoff, documented in -Notes. |

## Telemetry, Privacy, and Data Exfiltration to Vendor

*Data governance / privacy compliance (GDPR, OCIPA), insider-exfil surface*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Diagnostic data minimized + WER/CEIP/feedback/typing off | **closed** | low | 1 | ~25 privacy settings. On Home/Pro (Core) Windows floors AllowTelemetry at 1 - the tool warns and sets the lowest the edition allows; only Enterprise/Education reach 0. |
| Windows Recall (AI screen capture) disabled | **closed** | medium | 2 | AllowRecallEnablement=0 + DisableAIDataAnalysis=1. 24H2 Copilot+ screenshot archiver - severe privacy/legal/exfil risk. |
| Copilot / Cortana / web-search / cloud-clipboard off | **closed** | low | 1 | Disables AI-assistant and cloud-search data paths. Copilot executes remote content in-shell (prompt-injection surface). |
| Broader AI kill-switches (Click to Do, Edge Copilot sidebar, Notepad/Paint AI, Recall export, Start AI-search) | **closed** | medium | 2 | 24H2/25H2 Copilot+ AI surface beyond Recall: each a single reversible policy key. The OS-native AI models are continuous on-screen observers - a real exfil surface. AllowRecallExport=0 also blocks the Recall DB export API. |
| Windows AI Fabric service (WSAIFabricSvc) disabled | **closed** | low | 2 | Spawns WorkloadsSessionHost.exe which preloads AI models into 3-5GB RAM even when idle. Disabled via Disable-ServiceSafe (prior StartMode captured, reversible); skipped if absent on pre-Copilot+ builds. |
| Aggressive AI-eradication tactics (IFEO traps, cache purge, CDPSvc disable) | **not_covered** | medium | 4 | STILL DECLINED: IFEO Debugger traps are MITRE T1546.012 persistence that EDR flags; cache purge (ukg.db/ActivitiesCache.db) is destructive/irreversible; CDPSvc is a kernel dependency (BSOD risk). Manual cache-purge paths documented in -Notes for user discretion. NOTE: the deny-SYSTEM ACL tactic is now a separate GATED opt-in (see next row). |
| AI-key deny-SYSTEM ACL lock (survive-updates persistence) | **opt_in** | high | 4 | Extra-security option 12. Denies SYSTEM write on the WindowsAI/WindowsCopilot policy keys so a Windows Update running as SYSTEM cannot re-enable AI. DELIBERATELY breaks part of the servicing model - can make updates fail/partially-apply (a patch-integrity risk) and may be flagged as OS tampering by EDR. Gated behind a strict typed phrase ('LOCK AI KEYS'), reversible (records an undo that removes the deny ACE + restores inheritance, and prints the manual restore command). SAFER ALTERNATIVE the tool recommends: just re-run the hardening after major updates. Off by default for all these reasons. AUDITABLE: the read-only Verify (menu 3) and the -AuditReport HTML now detect and report the deny-SYSTEM ACE with a caution that it can block updates, so the locked state is never invisible to an auditor. |

## Audit Logging and Forensic Readiness

*MITRE ATT&CK detection coverage (all tactics), DFIR*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| PowerShell script-block / module / transcription logging | **closed** | high | 2 | The forensic-evidence layer - records de-obfuscated PowerShell incl. encoded commands. Without it an intrusion leaves no trace. |
| Advanced audit policy + enlarged event logs | **closed** | medium | 2 | Event log sized via -EventLogSizeMB (default 1024MB in the tested run). STIG wants >=1 week of records. |
| Configuration drift monitoring (scheduled) | **not_covered** | low | 2 | The tool ships a read-only Verify + HTML audit report, but not a standing scheduled drift monitor. That is a SIEM/monitoring-pipeline responsibility. |
| Detection of the AI-key ACL lock in the read-only audit | **closed** | low | 2 | Because the ACL lock (opt-in option 12) is an ACL change not a registry value, the value-based checks cannot see it. Verify reads the ACL directly and reports an INFO line when SYSTEM is denied write, with a caution that it can block Windows Update. Closes the 'tool can make a change it cannot see' gap (bug-26 discipline). |

## Lock Screen and Physical Console

*MITRE ATT&CK T1078 (Valid Accounts via unlocked console)*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Auto-lock idle / hide last user / require Ctrl+Alt+Del / no lock-screen camera-slideshow | **closed** | medium | 1 | InactivityTimeoutSecs=900, DontDisplayLastUserName, DisableCAD=0 (require it), NoLockScreenCamera/Slideshow. |

## Cloud/Domain-Managed Controls (Out of Scope)

*n/a - infrastructure-dependent*

| control | coverage | risk | tier | context |
|---|---|---|---|---|
| Windows LAPS AutomaticAccountManagement / dMSA logons | **not_covered** | medium | 2 | Requires a Microsoft Entra ID or Active Directory backend to escrow/rotate. Inert on a standalone box; deploy via Intune/AD. |
| WDAC enforcement, ISG, Managed Installers | **not_covered** | high | 3 | Needs Intune/cloud telemetry and a signed rollout. The tool provides audit-mode WDAC scaffolding only. |

## Operational Lifecycle

Beyond one-shot hardening, the tool manages the operational reality that a locked box still has to live: connect to hotel wifi, print, reach a share, adopt a device - then re-lock. These are not controls but the lifecycle around them.

| feature | coverage | notes |
|---|---|---|
| Temporary self-reverting unlocks | **closed** | Fail-closed by design (capture -> save-state -> apply -> arm auto-relock). State in ACL-locked .harden-unlocks/. UNVERIFIED on hardware: whether the schtasks auto-relock actually fires is the one thing only a live test confirms. |
| Reversibility | **closed** | Every Set-Reg captures prior state; -DryRun previews; an undo script is generated next to the .ps1; System Restore point created before apply. |
| Audit evidence | **closed** | -AuditReport produces a self-contained HTML control->state->PASS/FAIL report reflecting live state. Inline -Item labels are the control names; -Notes lists known gaps. |
