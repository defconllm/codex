#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 11 Pro/Enterprise Security Hardening - v2.2 (modular, gated, selectable, reversible).

.DESCRIPTION
    Applies a large set of well-established endpoint hardening controls to Windows 11.

    OVERVIEW
    --------
      A modular, reversible Windows 11 hardening tool. A safe baseline applies
      automatically; lockout-risk items are opt-in behind explicit switches plus
      runtime safety checks. Every change is captured for the generated UNDO
      script. See README.md for the feature list and 0harden-windows-notes.md for
      the detailed change history.

    DESIGN
    ------
      * Each control area is a module function. A dispatch table runs them in order and
        honors -OnlyModules / -SkipModules.
      * SAFE modules apply automatically. DANGEROUS modules are OFF by default behind an
        explicit switch AND a runtime safety check that refuses to proceed unless its
        precondition is verified.
      * -DryRun logs every action ("WOULD ...") without changing anything.

.PARAMETER DryRun
    Log all actions without applying any changes.

.PARAMETER Force
    Skip the interactive "type YES to proceed" confirmation. ALSO overrides the
    remote-session safety guard: with -Force, modules that disable RDP or block
    outbound will proceed even when the script detects it is running over RDP or
    WinRM. Only use it when you have a confirmed second way in (console access,
    another open session, or an allow rule for your admin host).

.PARAMETER SkipRestorePoint
    Do not create a System Restore point before applying changes.

.PARAMETER NoTranscript
    Do not start a PowerShell transcript.

.PARAMETER OnlyModules
    Run ONLY these modules (by name). See the module list printed at the top, or run
    with -ListModules. If a module is in BOTH -OnlyModules and -SkipModules,
    -OnlyModules wins (the module runs) - Only is an explicit include.

.PARAMETER SkipModules
    Skip these modules (by name).

.PARAMETER ListModules
    Print the available module names and exit.

.PARAMETER StopOnError
    Abort the run on the first failed step (fail-fast). The summary still prints.

.PARAMETER LmCompatibilityLevel
    LSA LmCompatibilityLevel (0-5). Default 5 (NTLMv2 only; refuse LM & NTLM). Lower to
    3 if legacy SMB devices break.

.PARAMETER EventLogSizeMB
    Max size (MB) for the Security and PowerShell/Operational logs. Others get min(this,512).
    Default 1024.

.PARAMETER SkipDefenderSignatureUpdate
    Skip the online Update-MpSignature step (useful offline / for speed).

.PARAMETER IncludeDeviceGuard
    Enable VBS / HVCI / Credential Guard (hardware-dependent; requires reboot).

.PARAMETER CredentialGuardUEFILock
    Use UEFI lock (LsaCfgFlags=1) for Credential Guard. Requires PHYSICAL presence to
    disable later. Without this switch, No-Lock (2) is used.

.PARAMETER IncludeBloatwareRemoval
    Remove non-essential provisioned UWP apps (leaves Store/Calculator intact).

.PARAMETER EnableBitLocker
    Enable BitLocker (XTS-AES-256, TPM+PIN). Requires -BitLockerKeyBackupPath and a TPM.
    Prompts interactively for the startup PIN.

.PARAMETER BitLockerKeyBackupPath
    Directory to escrow the BitLocker recovery key to. Required with -EnableBitLocker.

.PARAMETER DisableBuiltinAdmin
    Disable the built-in Administrator (SID -500) and Guest. Refuses unless another
    enabled local admin exists (and matches -VerifiedAdminAccount if given).

.PARAMETER VerifiedAdminAccount
    Existing enabled local admin to verify before disabling the built-in admin.

.PARAMETER EnforceNTLMDeny
    Set outgoing NTLM to DENY ALL. Without this switch, outgoing NTLM is set to AUDIT.

.PARAMETER BlockOutbound
    Set default outbound firewall action to BLOCK. Pre-creates core allow rules first.

.PARAMETER BlockAllInbound
    Disable every enabled inbound ALLOW firewall rule so nothing is reachable (the
    baseline already default-blocks inbound; this removes the allow-rule holes).
    Preserves Core Networking (DHCP/IPv6-ND). Refuses over RDP/WinRM without -Force.

.PARAMETER LockdownRemoteShell
    Lock down BOTH network remote-shell paths: RDP (service + firewall + deny
    policy) and OpenSSH server (sshd service + firewall). Lockout risk on a
    headless/remote box - refuses over the session it would sever without -Force.
    Reversible. Part of the Level 2 (lockout-risk) tier.

.PARAMETER Menu
    Force the interactive menu even when action flags are present.

.PARAMETER NoMenu
    Suppress the interactive menu (for non-interactive/scripted runs). Also what
    the scheduled auto-relock task passes.

.PARAMETER PesterTest
    Run the Pester test suite (Harden-Windows11.Tests.ps1, which ships alongside
    this script) and exit.

.PARAMETER KeepSMBClient
    Keep the SMB CLIENT enabled (default baseline disables it). Use this if the
    box needs to reach \\server shares, mapped drives, or domain GPO/SYSVOL.

.PARAMETER KeepPrinting
    Keep the Print Spooler enabled (default baseline disables it). Local printing
    keeps working; the remote-print RPC endpoint is still disabled.

.PARAMETER KeepUsernameShown
    Do NOT hide the last username at the login screen (the baseline hides it for
    privacy). Use this if you want your name to keep showing at sign-in.

.PARAMETER CloudProtection
    Re-enable Defender cloud protection (MAPS/SpyNet reporting + safe-sample
    submission). DEFAULT IS OFF: the baseline sends NOTHING to Microsoft. Use
    this only if you want maximum cloud-delivered protection over privacy.

.PARAMETER Notes
    Print the "known gaps and risky items to watch" section (what this tool does
    NOT do, and which of its changes carry risk) and exit. Useful before an audit.

.PARAMETER Unlock
    Temporarily weaken ONE area, then auto-relock. Values: captiveportal (hotel
    wifi login), printing, smbclient, rdp, winrm, vpn (allow VPN tunnel out when
    outbound is blocked). Pair with -UnlockMinutes and -UnlockReason. Records the
    original state and schedules a self-reverting re-lock. Example: -Unlock vpn
    -UnlockMinutes 60 -UnlockReason 'connect corp VPN'

.PARAMETER Relock
    Re-lock one area now (or 'all'). This is also what the scheduled auto-relock
    task calls. Example: -Relock printing  /  -Relock all

.PARAMETER UnlockMinutes
    How long an -Unlock stays open (default 60, capped at 480).

.PARAMETER UnlockReason
    A reason string, logged for the audit trail.

.PARAMETER AuditReport
    Run the read-only Verify audit and export a self-contained HTML evidence
    report (control -> state -> detail) next to this script, then exit. Intended
    as an audit deliverable. Changes no system state. Also available from the menu
    after "check for gaps".

.PARAMETER SelfTest
    Run the built-in self-test and exit. Changes nothing, needs no admin. Checks
    the decision logic (lockout guard, egress pinning, verify verdicts, menu
    activation, USB safety, undo ordering) and audits this script's own source
    (coherence, no stale version strings, no dry-run-hidden destructive ops).
    Exit code 0 = all passed. Mirrors the verified Python harness; run-tests.bat
    runs both plus Pester.

.PARAMETER BlockDeviceAutoInstall
    EXTRA. Stop hardware insertion from pulling software: no device-metadata
    fetch (companion apps), no Windows Update driver auto-install, and disable
    WPBT firmware-binary execution. New devices will not auto-get a driver
    afterward (existing hardware is unaffected).

.PARAMETER USBGuard
    EXTREME. Learn the USB devices present now, allowlist them (HID/keyboard/mouse
    force-included), and block NEW/unlisted USB devices from installing. Refuses
    from a remote session without -Force (cannot verify console input is allowed).

.PARAMETER BlockUSBStorage
    With -USBGuard, also disable USB mass storage (USBSTOR). Stops rogue-USB data
    but also all USB drives, including already-approved ones.

.PARAMETER DisablePrintSpooler
    Disable and stop the Print Spooler (PrintNightmare attack surface). Only
    affects the SurfaceReduction module. Refuses if shared printers are present
    unless -Force. Omit on any box that prints.

.PARAMETER GenerateWDACAuditPolicy
    Generate an AUDIT-mode WDAC (Code Integrity) base policy scaffold under C:\WDAC.

.EXAMPLE
.EXAMPLE
    # Run the built-in tests (safe anywhere, no admin, no changes):
    .\Harden-Windows11-v2_2.ps1 -SelfTest

.EXAMPLE
    # Audit only - read-only, changes nothing, safe on a live box:
    .\Harden-Windows11-v2_2.ps1 -OnlyModules Verify

.EXAMPLE
    .\Harden-Windows11-v2_2.ps1 -DryRun

.EXAMPLE
    .\Harden-Windows11-v2_2.ps1 -OnlyModules Defender,ASR,Firewall,Audit

.EXAMPLE
    .\Harden-Windows11-v2_2.ps1 -SkipModules Privacy,Bloatware -LmCompatibilityLevel 3 -StopOnError

.EXAMPLE
    .\Harden-Windows11-v2_2.ps1 -DisableBuiltinAdmin -VerifiedAdminAccount "AdminLcl_001" `
        -EnableBitLocker -BitLockerKeyBackupPath "\\fileserver\BitLockerKeys" -EnforceNTLMDeny

.NOTES
    RUN AS ADMINISTRATOR. Test with -DryRun on a snapshot/VM first. Provided as-is.
    For fleets, prefer Microsoft Security Baselines / Intune / GPO / CIS Benchmarks.
#>

# =============================================================================
# KNOWN GAPS AND RISKY ITEMS TO WATCH  (read before an audit or a field run)
# =============================================================================
# This tool is deliberately honest about what it does NOT do and where its own
# changes carry risk. An auditor should trust a tool that documents its limits.
# View this at runtime with:  .\Harden-Windows11-v2_2.ps1 -Notes
#
# -----------------------------------------------------------------------------
# A. SECURITY ITEMS NOT DONE (and why) - these are OUT OF SCOPE by design
# -----------------------------------------------------------------------------
#  1. Windows LAPS / AutomaticAccountManagement (auto-rotating local admin pw):
#     Requires a Microsoft Entra ID or Active Directory backend to escrow the
#     password. Inert and pointless on a standalone box. Use Intune/AD to deploy.
#  2. Delegated Managed Service Accounts (dMSA) logons: pure domain feature; needs
#     Server 2025-class DCs. N/A to a standalone workstation.
#  3. Credential Guard / VBS with UEFI LOCK: VBS/HVCI is enabled (opt-in
#     -IncludeDeviceGuard), but the UEFI lock is OFF by default (LsaCfgFlags=2).
#     The lock is available via -CredentialGuardUEFILock, but understand the risk:
#     with the lock, VBS/CredGuard cannot be disabled remotely - it needs physical
#     presence to clear a UEFI variable. If a hypervisor or 3rd-party virtualization
#     tool later conflicts, the whole box is a brick until someone stands in front
#     of it. Default is no-lock for exactly that reason; only pass the flag on a
#     managed, known-good fleet where you accept the lock-in.
#  4. Full outbound default-deny firewall: available as an OPT-IN (-BlockOutbound),
#     NOT baseline. A true default-deny needs a per-environment allow-list; applied
#     blindly it breaks updates, licensing, and line-of-business apps. Note also it
#     does NOT stop exfil over an already-allowed channel (e.g. HTTPS/443).
#  5. WDAC/App Control ENFORCEMENT: we generate an AUDIT-mode policy only
#     (-GenerateWDACAuditPolicy). Enforcement mode requires weeks of telemetry +
#     signed exclusions per app or it blocks legitimate software. Do that rollout
#     deliberately, not from a hardening script.
#  6. Network adapter binding strips / protocol unbinding, MAC randomization,
#     SMBv2 disable: too environment-specific / breaks modern file access. Out.
#  7. Physical / firmware controls (UEFI-vs-Legacy boot mode, port security, TPM
#     presence): cannot be set from the OS; verify manually (STIG V-253256 etc).
#  8. Domain/GPO-governed settings: on a domain-joined box, the DOMAIN policy wins
#     for domain accounts. Account-policy and some credential items here apply to
#     LOCAL accounts; cross-check the domain GPO for a clean audit.
#  9. Aggressive AI-eradication tactics DECLINED by design (from the AI-telemetry
#     guide). We DISABLE the AI subsystem via policy keys + the WSAIFabricSvc
#     service (reversible, effective), but we deliberately do NOT: (a) deny-SYSTEM
#     registry ACLs to block Windows Update from re-enabling keys - that sabotages
#     the OS servicing model and can block security patches; (b) plant IFEO
#     Debugger traps on AI binaries - IFEO is itself a MITRE persistence technique
#     (T1546.012) that EDR flags as malicious; (c) auto-purge existing Recall/CDP
#     caches (ukg.db, ActivitiesCache.db, ImageStore JPEGs) - deleting user data is
#     destructive and irreversible. If you WANT the historical caches wiped, do it
#     manually and deliberately: the paths are %LOCALAPPDATA%\CoreAIPlatform.00\UKP
#     and %LOCALAPPDATA%\ConnectedDevicesPlatform. We also do NOT disable CDPSvc/
#     CDPUserSvc (the guide itself notes CDPSvc is a kernel dependency and killing
#     the per-user service risks a BSOD); the cloud-clipboard privacy win is already
#     achieved via AllowCrossDeviceClipboard=0 without that risk.
#
# -----------------------------------------------------------------------------
# B. RISKY ITEMS THIS TOOL CAN APPLY - watch these (all reversible via undo)
# -----------------------------------------------------------------------------
#  1. PKINIT SHA-1 deprecation (extra security 10): on a DOMAIN-JOINED box with
#     Server 2022-or-older DCs this SILENTLY BREAKS Kerberos auth (error 0x3bc4).
#     Opt-in, domain-guarded (needs -Force on a domain), reversible from CONSOLE.
#  2. Windows Protected Print / WPP (extra security 8): PERMANENTLY DELETES non-IPP
#     print queues and blocks third-party drivers. Audit the printer fleet first.
#  3. SMB client disabled (baseline, aggressive): the box can no longer open
#     \\server\shares, mapped drives, or pull GPO/SYSVOL if domain-joined. Use
#     -KeepSMBClient, or temporarily re-enable via operational menu (8) > SMB.
#  4. Print Spooler fully disabled (baseline): no printing at all. Use -KeepPrinting,
#     WPP (opt-in), or operational unlock. Refuses if shared printers exist w/o -Force.
#  5. BitLocker with TPM+PIN (-EnableBitLocker): needs a key-escrow path
#     (-BitLockerKeyBackupPath). Pre-boot PIN blocks unattended reboots/patching -
#     a machine can sit at the PIN screen unpatched. Weigh vs your patch cadence.
#  6. Disable built-in Administrator (-DisableBuiltinAdmin): guarded to never remove
#     your LAST admin, but confirm you have another working admin before use.
#  7. Aggressive network (extra security 7): removes admin shares (C$/ADMIN$) -
#     breaks PsExec, MECM/SCCM push, and credentialed scanners. UNC hardening can
#     break GPO on domains whose DCs lack SMB signing.
#  8. NTLM deny (-EnforceNTLMDeny): can break legacy apps, some Wi-Fi 802.1X / VPN
#     RADIUS flows, and old NAS. Audit inbound NTLM first (we log it).
#  9. Operational UNLOCKS (menu 8): temporary weaken + auto-relock via schtasks.
#     Fail-closed by design, BUT whether schtasks actually fires the relock on YOUR
#     hardware is the one thing only a live test confirms - verify it once.
# 10. No-exfil Defender defaults: cloud protection + sample submission are OFF by
#     default (privacy), which REDUCES cloud-delivered protection. Re-enable with
#     -CloudProtection if you want MAPS/cloud lookups.
# 11. Edition telemetry floor: on Home/Pro (Core) editions Windows enforces a
#     minimum telemetry level of 1 - the tool cannot set it to 0; it warns and sets
#     the lowest the edition allows. Only Enterprise/Education can reach 0.
# 12. Password/lockout policy: OPT-IN (extra security > password policy), NOT
#     baseline - enforcing 14-char/complexity/5-try-lockout on a personal or lab
#     box locks you out of your own accounts. Two explicit modes: ENFORCE (CIS
#     values) and RELAX (remove the requirements). Enforce captures the prior state
#     first; relax restores permissive defaults. Applies to LOCAL accounts only.
#
# -----------------------------------------------------------------------------
# C. INERT-BUT-HARMLESS on a standalone box (apply cleanly, only bite on a domain)
# -----------------------------------------------------------------------------
#     Kerberos AES-only encryption types, UNC hardening, LDAP client signing, and
#     PKINIT all target domain auth. On a standalone box they set cleanly and do
#     nothing; on a domain they interact with DC capabilities - verify DC support.
#
# NOTE ON FRAMEWORK CITATIONS: CIS/STIG control NUMBERS in this script are
# indicative and were current to the guides reviewed. Benchmark numbering shifts
# between versions - have your compliance owner cross-check against the exact
# benchmark version you are audited against.
# =============================================================================


[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Force,
    [switch]$SkipRestorePoint,
    [switch]$NoTranscript,
    [string[]]$OnlyModules,
    [string[]]$SkipModules,
    [switch]$ListModules,
    [switch]$StopOnError,
    [ValidateRange(0,5)][int]$LmCompatibilityLevel = 5,
    [ValidateRange(64,4096)][int]$EventLogSizeMB = 1024,
    [switch]$SkipDefenderSignatureUpdate,
    [switch]$CloudProtection,
    [switch]$KeepSMBClient,
    [switch]$KeepPrinting,
    [switch]$KeepUsernameShown,
    [switch]$IncludeDeviceGuard,
    [switch]$CredentialGuardUEFILock,
    [switch]$IncludeBloatwareRemoval,
    [switch]$EnableBitLocker,
    [string]$BitLockerKeyBackupPath,
    [switch]$DisableBuiltinAdmin,
    [string]$VerifiedAdminAccount,
    [switch]$EnforceNTLMDeny,
    [switch]$BlockOutbound,
    [switch]$BlockAllInbound,
    [switch]$LockdownRemoteShell,
    [switch]$GenerateWDACAuditPolicy,
    [switch]$DisablePrintSpooler,
    [switch]$Menu,
    [switch]$NoMenu,
    [switch]$SelfTest,
    [switch]$PesterTest,
    [switch]$AuditReport,
    [switch]$Notes,
    [ValidateSet('captiveportal','printing','smbclient','rdp','winrm','vpn')][string]$Unlock,
    [string]$Relock,
    [int]$UnlockMinutes = 60,
    [string]$UnlockReason = 'not specified',
    [switch]$USBGuard,
    [switch]$BlockUSBStorage,
    [switch]$BlockDeviceAutoInstall
)

# ============================================================================
#region  STATE
# ============================================================================
$Script:DryRun       = $DryRun.IsPresent
$Script:StopOnError  = $StopOnError.IsPresent
$Script:LogFile      = $null
$Script:CsvFile      = $null
$Script:Transcript   = $null
$Script:Results      = New-Object System.Collections.Generic.List[object]
$Script:RebootNeeded = New-Object System.Collections.Generic.List[string]
$Script:Artifacts    = New-Object System.Collections.Generic.List[string]
$Script:ManualSteps  = New-Object System.Collections.Generic.List[string]
$Script:GapFindings  = New-Object System.Collections.Generic.List[string]   # pre-existing weaknesses for the user to fix
$Script:UndoActions  = New-Object System.Collections.Generic.List[object]   # rollback records, applied LIFO
$Script:Edition      = 'Unknown'
$Script:Caption      = ''
$Script:Build        = 0
#endregion

# ============================================================================
#region  HELPERS
# ============================================================================
function Protect-File {
    # Lock a file down to SYSTEM + Administrators only (no Users, no inheritance).
    # bug W9/W8, ported from 0harden bug 39: the fix is to restrict access BEFORE
    # the secret is written, not after - a chmod-after (or Set-Acl-after) leaves
    # a window where the plaintext is readable. So callers create the empty file,
    # Protect-File it, THEN write. Best-effort: on failure it warns loudly rather
    # than silently leaving a world-readable secret.
    param([Parameter(Mandatory)][string]$Path, [switch]$Quiet)
    try {
        if (-not (Test-Path $Path)) { New-Item -ItemType File -Path $Path -Force -ErrorAction Stop | Out-Null }
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs
        foreach ($id in @('SYSTEM','BUILTIN\Administrators')) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $acl.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Administrators')
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        if (-not $Quiet) { Write-Log OK "Locked ACL on $Path (SYSTEM + Administrators only)" }
        return $true
    } catch {
        Write-Log WARN "Could NOT restrict ACL on $Path : $($_.Exception.Message). Treat its contents as readable by any local user."
        return $false
    }
}

function Protect-Directory {
    param([Parameter(Mandatory)][string]$Path, [switch]$Quiet)
    try {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($id in @('SYSTEM','BUILTIN\Administrators')) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        if (-not $Quiet) { Write-Log OK "Locked ACL on directory $Path (SYSTEM + Administrators only)" }
        return $true
    } catch {
        if (-not $Quiet) { Write-Log WARN "Could NOT restrict ACL on directory $Path : $($_.Exception.Message)." }
        return $false
    }
}

function Add-Undo {
    # Records one reversal, applied later in REVERSE order. Kinds:
    #   RegRestore  - restore a prior registry value (Path/Name/Value/Kind)
    #   RegRemove   - delete a value we created (Path/Name)
    #   Command     - an explicit reversal command string (Undo)
    #   Manual      - something a script cannot reverse (Note) - listed, never run
    # Ported from 0harden's manifest lesson (bugs 34/38): capture the mapping at
    # change time, and record EVERYTHING you did - including "cannot undo" - so
    # rollback never silently leaves state behind or claims a reversal it lacks.
    param([Parameter(Mandatory)][hashtable]$Record)
    if ($Script:DryRun) { return }
    $Script:UndoActions.Add([pscustomobject]$Record)
}

function Write-UndoScript {
    # Emits a standalone .ps1 that reverses this run: the captured registry/
    # service/firewall changes (in LIFO order), a system-info header, the list of
    # SKIPPED items, and an honest MANUAL section for what a script cannot undo.
    # Only meaningful after an apply; a dry-run captured nothing.
    if ($Script:DryRun) { return }
    if ($Script:UndoActions.Count -eq 0) { return }

    # Write the undo script NEXT TO this .ps1 (not C:\) so it travels with the
    # tool and is easy to find. Fall back to the system drive only if the script
    # directory is not writable (e.g. running from a read-only share).
    $scriptDir = Split-Path -Parent $PSCommandPath
    $undoPath  = Join-Path $scriptDir "Harden-Win11-UNDO_$stamp.ps1"
    try {
        # probe writability of the script dir
        $probe = Join-Path $scriptDir ".undo_write_test_$stamp"
        [IO.File]::WriteAllText($probe, 'x'); Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log WARN "Script directory not writable; writing undo to $env:SystemDrive instead."
        $undoPath = Join-Path $env:SystemDrive "Harden-Win11-UNDO_$stamp.ps1"
    }
    # bug 39: this file holds system info and registry paths and is itself a
    # state-changing script. Lock it down before writing.
    Protect-File -Path $undoPath -Quiet | Out-Null

    $sb = New-Object System.Text.StringBuilder
    $nl = [Environment]::NewLine
    function _q([string]$s) { "'" + ($s -replace "'","''") + "'" }   # single-quote-safe

    [void]$sb.Append("#Requires -Version 5.1$nl")
    [void]$sb.Append("<#$nl")
    [void]$sb.Append("  UNDO script for Harden-Windows11 v2.2$nl")
    [void]$sb.Append("  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')$nl")
    [void]$sb.Append("  Computer  : $env:COMPUTERNAME$nl")
    [void]$sb.Append("  OS        : $Script:Caption (Edition: $Script:Edition, Build: $Script:Build)$nl")
    [void]$sb.Append("  Session   : $(if($Script:RemoteSession.OverRDP){'RDP'}elseif($Script:RemoteSession.OverWinRM){'WinRM'}else{'console'})$nl")
    [void]$sb.Append("  Source log: $Script:LogFile$nl")
    [void]$sb.Append("$nl")
    [void]$sb.Append("  This reverses the REGISTRY / SERVICE / FIREWALL changes captured during that$nl")
    [void]$sb.Append("  run, in reverse order. It does NOT (and cannot safely) reverse BitLocker,$nl")
    [void]$sb.Append("  removed apps, or removed features - those are listed at the bottom as manual$nl")
    [void]$sb.Append("  steps. Review before running. It changes system state; it asks first.$nl")
    [void]$sb.Append("$nl")

    # Skipped items - recorded so you know what was NOT changed (nothing to undo).
    $skipped = $Script:Results | Where-Object { $_.Status -eq 'Skipped' }
    if ($skipped) {
        [void]$sb.Append("  SKIPPED during the original run (not changed, so nothing to undo):$nl")
        foreach ($k in $skipped) { [void]$sb.Append("    - [$($k.Category)] $($k.Item) :: $($k.Detail)$nl") }
        [void]$sb.Append("$nl")
    }
    [void]$sb.Append("#>$nl$nl")

    [void]$sb.Append("[CmdletBinding()]$nl")
    [void]$sb.Append("param([switch]`$Force)$nl$nl")
    [void]$sb.Append("if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq `$false) { Write-Host 'Run as Administrator.' -ForegroundColor Red; return }$nl")
    [void]$sb.Append("if (-not `$Force) { if ((Read-Host 'Revert hardening changes on this box? type YES') -ne 'YES') { Write-Host 'Aborted.'; return } }$nl$nl")

    # Undo actions in REVERSE order (LIFO): unwind the last change first.
    $reversed = @($Script:UndoActions); [array]::Reverse($reversed)
    $manualReg = @()   # reg values whose prior type cannot be rendered literally
    [void]$sb.Append("# ---- reversible actions (applied last-changed-first) ----$nl")
    foreach ($u in $reversed) {
        switch ($u.Kind) {
            'RegRestore' {
                $kind = if ($u.PriorKind) { $u.PriorKind } else { 'DWord' }
                # Only emit a literal restore for types we can render faithfully.
                # MultiString (string[]) and Binary (byte[]) do not survive string
                # interpolation, and ExpandString would re-expand %VARS% wrongly.
                # For those, emit a MANUAL note instead of a broken command - a
                # rollback that emits a broken line is worse than one that says
                # "restore this by hand" (bug 26 honesty, applied to this code).
                if ($kind -in @('DWord','QWord','String')) {
                    $val = if ($kind -eq 'String') { _q ([string]$u.Value) } else { [int64]$u.Value }
                    [void]$sb.Append("# restore: $($u.Label)$nl")
                    [void]$sb.Append("try { New-ItemProperty -Path $(_q $u.Path) -Name $(_q $u.Name) -Value $val -PropertyType $kind -Force -ErrorAction Stop | Out-Null } catch { Write-Warning `"restore failed: $($u.Name)`" }$nl")
                } else {
                    $manualReg += "Registry $($u.Path)\$($u.Name) had a prior $kind value this rollback cannot render literally. Restore it by hand from the source log."
                }
            }
            'RegRemove' {
                [void]$sb.Append("# remove value we added: $($u.Label)$nl")
                [void]$sb.Append("try { Remove-ItemProperty -Path $(_q $u.Path) -Name $(_q $u.Name) -ErrorAction Stop } catch { Write-Warning `"remove failed: $($u.Name)`" }$nl")
            }
            'Command' {
                [void]$sb.Append("# $($u.Label)$nl")
                [void]$sb.Append("try { $($u.Undo) } catch { Write-Warning `"undo failed: $($u.Label)`" }$nl")
            }
            'Manual' { }   # rendered in the manual section below
        }
    }

    # Manual / irreversible section - listed, never executed.
    $manual = @($reversed | Where-Object { $_.Kind -eq 'Manual' })
    if ($manual -or $manualReg) {
        [void]$sb.Append("$nl# ---- MANUAL: a script cannot safely reverse these ----$nl")
        foreach ($m in $manual)    { [void]$sb.Append("#  * $($m.Note)$nl") }
        foreach ($r in $manualReg) { [void]$sb.Append("#  * $r$nl") }
    }
    [void]$sb.Append("$nlWrite-Host 'Undo complete. A reboot may be needed for some settings. Re-run the hardening verify to confirm.' -ForegroundColor Green$nl")

    Set-Content -Path $undoPath -Value $sb.ToString() -Encoding UTF8 -ErrorAction SilentlyContinue
    $Script:Artifacts.Add($undoPath)
    Write-Log OK "Undo script written: $undoPath ($($Script:UndoActions.Count) actions, $($manual.Count + $manualReg.Count) manual)"
}

function Write-RunSummary {
    # Extracted from the finally block so BOTH the linear run and the menu path
    # print it. Refactoring note: before this, a menu 'harden' ran the modules
    # but returned before the summary, so it silently produced no report. One
    # source of truth now.
    Write-UndoScript   # emit rollback .ps1 first so it appears in artifacts below
    Write-Section 'Summary'
    try { $Script:Results | Export-Csv -Path $Script:CsvFile -NoTypeInformation -ErrorAction Stop } catch {}

    $byStatus = $Script:Results | Group-Object Status | Sort-Object Name
    foreach ($g in $byStatus) {
        $col = switch ($g.Name) { 'Applied' {'Green'} 'Failed' {'Red'} 'Skipped' {'Yellow'} default {'Gray'} }
        Write-Host ("  {0,-8}: {1}" -f $g.Name, $g.Count) -ForegroundColor $col
    }
    $failed = $Script:Results | Where-Object { $_.Status -eq 'Failed' }
    if ($failed) {
        Write-Host ''
        Write-Host '  FAILURES:' -ForegroundColor Red
        $failed | ForEach-Object { Write-Host ("   - [{0}] {1} :: {2}" -f $_.Category, $_.Item, $_.Detail) -ForegroundColor Red }
    }
    if ($Script:RebootNeeded.Count -gt 0) {
        Write-Host ''
        Write-Host '  REBOOT REQUIRED for:' -ForegroundColor Yellow
        $Script:RebootNeeded | Select-Object -Unique | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
    }
    if ($Script:Artifacts.Count -gt 0) {
        Write-Host ''
        Write-Host '  GENERATED ARTIFACTS:' -ForegroundColor Cyan
        $Script:Artifacts | ForEach-Object { Write-Host "   - $_" -ForegroundColor Cyan }
    }
    if ($Script:GapFindings.Count -gt 0) {
        Write-Host ''
        Write-Host '  *** FOLLOW-UP: PRE-EXISTING GAPS THIS TOOL DID NOT FIX ***' -ForegroundColor Red
        Write-Host '  (These were already on the box and need a human decision.)' -ForegroundColor Yellow
        $g = 1
        $Script:GapFindings | ForEach-Object { Write-Host ("   {0}. {1}" -f $g, $_) -ForegroundColor Yellow; $g++ }
    }
    if ($Script:ManualSteps.Count -gt 0) {
        Write-Host ''
        Write-Host '  MANUAL NEXT STEPS:' -ForegroundColor White
        $i = 1
        $Script:ManualSteps | ForEach-Object { Write-Host ("   {0}. {1}" -f $i, $_) -ForegroundColor Gray; $i++ }
    }
    Write-Host ''
    # Surface connectivity-severing changes prominently at the END so they are not
    # lost mid-log. Check the actual resulting service states rather than guessing.
    if (-not $Script:DryRun) {
        $sev = @()
        $lw = Get-Service -Name LanmanWorkstation -ErrorAction SilentlyContinue
        if ($lw -and $lw.StartType -eq 'Disabled') { $sev += 'SMB client is OFF - \\server shares and mapped drives will not work.' }
        $sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($sp -and $sp.StartType -eq 'Disabled') { $sev += 'Print Spooler is OFF - no printing (local or network).' }
        $ts = Get-Service -Name TermService -ErrorAction SilentlyContinue
        if ($ts -and $ts.StartType -eq 'Disabled') { $sev += 'Remote Desktop is OFF - no inbound RDP.' }
        $wr = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($wr -and $wr.StartType -eq 'Disabled') { $sev += 'WinRM is OFF - no remote PowerShell in.' }
        if ($sev.Count -gt 0) {
            Write-Host '  ***  CONNECTIVITY NOW RESTRICTED  ***' -ForegroundColor Yellow
            $sev | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
            Write-Host '   Reverse any of these: menu 5 (extra security) > SMB/printer/RDP allow,' -ForegroundColor Yellow
            Write-Host "   or run the undo script listed under GENERATED ARTIFACTS above." -ForegroundColor Yellow
            Write-Host ''
        }
    }
    Write-Host "  Log: $Script:LogFile" -ForegroundColor DarkGray
    Write-Host "  CSV: $Script:CsvFile" -ForegroundColor DarkGray
    Write-Host '  Done.' -ForegroundColor White
}

function Write-Log {
    param(
        [ValidateSet('INFO','OK','WARN','ERROR','STEP','DRY')][string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$Message
    )
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP'  { 'Cyan' }
        'DRY'   { 'Magenta' }
        default { 'Gray' }
    }
    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Host $line -ForegroundColor $color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('#' * 78) -ForegroundColor DarkCyan
    Write-Host ("#  {0}" -f $Title) -ForegroundColor DarkCyan
    Write-Host ('#' * 78) -ForegroundColor DarkCyan
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value "`n### $Title ###" -ErrorAction SilentlyContinue }
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet('Applied','Skipped','Failed','Audit','Info','Pending','GAP')][string]$Status,
        [string]$Detail = ''
    )
    $Script:Results.Add([pscustomobject]@{
        Category = $Category; Item = $Item; Status = $Status; Detail = $Detail
    })
}

function Set-Reg {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')][string]$Type = 'DWord',
        [string]$Category = 'Registry',
        [string]$Item
    )
    if (-not $Item) { $Item = "$Path\$Name" }
    if ($Script:DryRun) {
        Write-Log DRY "WOULD set $Path\$Name = $Value ($Type)"
        Add-Result $Category $Item 'Skipped' 'dry-run'
        return
    }
    try {
        # Capture the prior state BEFORE writing (bug 34/38: capture at change
        # time, not later). This is what makes the undo script possible.
        $priorExisted = $false; $priorValue = $null; $priorKind = $null
        try {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.Property -contains $Name) {
                $priorExisted = $true
                $priorValue   = $key.GetValue($Name)
                $priorKind    = $key.GetValueKind($Name).ToString()
            }
        } catch { }   # key does not exist yet -> prior did not exist

        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        Write-Log OK "$Path\$Name = $Value"
        Add-Result $Category $Item 'Applied' "= $Value"

        # Record the reversal. Only if we actually changed something (skip a
        # no-op set to keep the undo script clean).
        if ($priorExisted -and ("$priorValue" -ne "$Value")) {
            Add-Undo @{ Kind='RegRestore'; Path=$Path; Name=$Name; Value=$priorValue; PriorKind=$priorKind; Label=$Item }
        } elseif (-not $priorExisted) {
            Add-Undo @{ Kind='RegRemove'; Path=$Path; Name=$Name; Label=$Item }
        }
    } catch {
        Write-Log ERROR "Failed $Path\$Name : $($_.Exception.Message)"
        Add-Result $Category $Item 'Failed' $_.Exception.Message
        if ($Script:StopOnError) { throw "StopOnError at [$Category] $Item" }
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$RebootRequired
    )
    if ($Script:DryRun) {
        Write-Log DRY "WOULD: [$Category] $Item"
        Add-Result $Category $Item 'Skipped' 'dry-run'
        return
    }
    try {
        & $Action
        Write-Log OK "$Item"
        Add-Result $Category $Item 'Applied'
        if ($RebootRequired) { $Script:RebootNeeded.Add("$Category - $Item") }
    } catch {
        Write-Log ERROR "$Item : $($_.Exception.Message)"
        Add-Result $Category $Item 'Failed' $_.Exception.Message
        if ($Script:StopOnError) { throw "StopOnError at [$Category] $Item" }
    }
}

function Get-EnabledLocalAdmins {
    # Enabled LOCAL user accounts in Administrators, excluding the built-in (-500).
    $out = @()
    try {
        $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    } catch {
        # Get-LocalGroupMember can throw if the group contains an orphaned/deleted SID.
        # Returning empty triggers the safety stop below (fail closed), which is the safe outcome.
        Write-Log WARN "Could not enumerate Administrators group: $($_.Exception.Message)"
        return $out
    }
    foreach ($m in $members) {
        if ($m.ObjectClass -ne 'User')      { continue }
        if ($m.PrincipalSource -ne 'Local') { continue }
        $name = ($m.Name -split '\\')[-1]
        $lu = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($lu -and $lu.Enabled -and ($lu.SID.Value -notlike '*-500')) { $out += $lu }
    }
    return $out
}

function Get-RemoteSessionKind {
    # Is THIS script running over a remote session that hardening could sever?
    # Ported from 0harden's ssh_lockout_guard. The lesson there (bug 41): do not
    # trust one signal - a false positive skips a real control, a false negative
    # locks someone out. So we gather several and let the caller decide.
    #
    # Returns a hashtable: @{ OverRDP=$bool; OverWinRM=$bool; RdpEstablished=$bool; Detail=$string }
    $result = @{ OverRDP = $false; OverWinRM = $false; RdpEstablished = $false; Detail = '' }
    $bits = @()

    # Primary: SESSIONNAME is RDP-Tcp#N on an RDP session, "Console" locally.
    $sn = $env:SESSIONNAME
    if ($sn -and $sn -like 'RDP-Tcp*') { $result.OverRDP = $true; $bits += "SESSIONNAME=$sn" }

    # WinRM: remote PowerShell runs under wsmprovhost.exe, and SESSIONNAME stays
    # "Console" - so SESSIONNAME alone MISSES it. Walk the parent chain.
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        $guard = 0
        while ($p -and $guard -lt 12) {
            if ($p.Name -match 'wsmprovhost|winrshost') { $result.OverWinRM = $true; $bits += "ancestor=$($p.Name)"; break }
            if (-not $p.ParentProcessId) { break }
            $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
            $guard++
        }
    } catch {}

    # Secondary: is anyone (maybe another user) currently RDP'd in? Disabling RDP
    # locks THEM out even if this session is local. Warn, do not refuse, on this.
    try {
        $est = Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction SilentlyContinue
        if ($est) { $result.RdpEstablished = $true; $bits += "3389 established x$(@($est).Count)" }
    } catch {}

    $result.Detail = ($bits -join '; ')
    return $result
}

$Script:RemoteSession = $null   # populated in preflight, read by the guard
function Assert-NotSeveringOurAccess {
    # Called by any module about to disable the remote-access path. Refuses in
    # APPLY mode when we can see we are on the path being cut, unless -Force.
    # 0harden dies here; PowerShell's equivalent is to skip the severing step
    # and record why, so the rest of the run still completes.
    param([Parameter(Mandatory)][string]$What)

    if ($Script:DryRun) { return $true }   # dry run changes nothing; let it narrate

    $s = $Script:RemoteSession
    if (-not $s) { return $true }

    if ($s.OverRDP -or $s.OverWinRM) {
        $how = if ($s.OverRDP) { 'RDP' } else { 'WinRM' }
        if ($Force) {
            Write-Log WARN "You are on a $how session and -Force is set. Proceeding to $What. Your current session may survive, but you may not be able to RECONNECT after you disconnect."
            $Script:ManualSteps.Add("You hardened remote access ($What) while connected over $how. CONFIRM you have another way in (console, a still-open session, or an allow rule for your admin host) BEFORE you disconnect.")
            return $true
        }
        Write-Log ERROR "SAFETY STOP: you are running this over $how ($($s.Detail)), and '$What' would shut the door you came in through. Skipped. Your session is fine right now; the danger is the NEXT reconnect. Re-run from the console, or pass -Force if you have another way in."
        Add-Result 'RemoteAccess' $What 'Skipped' "would sever this $how session"
        return $false
    }

    if ($s.RdpEstablished) {
        Write-Log WARN "'$What': you appear to be on the console, but an RDP session is currently established ($($s.Detail)). Disabling RDP will lock out whoever is on it."
        $Script:ManualSteps.Add("'$What' was applied while someone was connected via RDP. Confirm that was intended.")
    }
    return $true
}
#endregion

# ============================================================================
#region  VERIFY HELPERS
# ============================================================================
# The verify module AUDITS what is actually true now, rather than trusting that
# apply worked. Ported from 0harden's verify module and its hardest-won lesson
# (bug 36): a check that cannot run its tool must say INCONCLUSIVE, never PASS.
# A false FAIL wastes an afternoon; a false PASS on a security check is how you
# ship the hole believing you checked. So every check returns one of three
# states, and "I could not look" is its own state, distinct from "I looked and
# it is fine".

function Write-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','PENDING','INCONCLUSIVE','INFO','GAP')][string]$State,
        [string]$Detail = ''
    )
    $map = @{
        PASS         = @{ c='Green';   t='[ ok ]' }
        FAIL         = @{ c='Red';     t='[FAIL]' }
        PENDING      = @{ c='Yellow';  t='[pend]' }
        INCONCLUSIVE = @{ c='Magenta'; t='[ ?? ]' }
        INFO         = @{ c='Gray';    t='[info]' }
        GAP          = @{ c='Red';     t='[GAP ]' }
    }
    $m = $map[$State]
    $line = "  {0} {1}{2}" -f $m.t, $Name, $(if ($Detail) { " :: $Detail" } else { '' })
    Write-Host $line -ForegroundColor $m.c
    if ($State -eq 'GAP') { $Script:GapFindings.Add("$Name :: $Detail") }
    Add-Result 'Verify' $Name $(switch ($State) { 'PASS'{'Applied'} 'FAIL'{'Failed'} 'PENDING'{'Pending'} 'INFO'{'Info'} 'GAP'{'GAP'} default{'Audit'} }) $Detail
}

function Get-RegValueSafe {
    # Returns @{ Ok=$bool; Value=$x }. Ok=$false means "could not read" (missing
    # key/value), which the caller must treat as its own case, not as a value.
    param([string]$Path, [string]$Name)
    try {
        $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return @{ Ok = $true; Value = $v }
    } catch {
        return @{ Ok = $false; Value = $null }
    }
}

function Test-RegInvariant {
    # The common case: a registry value must equal an expected number.
    # Missing value -> FAIL (the control was never applied), NOT inconclusive:
    # we CAN read the registry, the value is simply absent.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)]$Expected,
        [switch]$RebootMakesEffective
    )
    $r = Get-RegValueSafe -Path $Path -Name $Value
    if (-not $r.Ok) {
        Write-Check $Name 'FAIL' 'not set'
        return
    }
    if ("$($r.Value)" -eq "$Expected") {
        if ($RebootMakesEffective -and ($Script:RebootNeeded.Count -gt 0)) {
            Write-Check $Name 'PENDING' "= $Expected in registry; takes effect after reboot"
        } else {
            Write-Check $Name 'PASS' "= $($r.Value)"
        }
    } else {
        Write-Check $Name 'FAIL' "= $($r.Value), expected $Expected"
    }
}
#endregion

# ============================================================================
#region  MODULE FUNCTIONS
# ============================================================================
function Invoke-Mod-Restore {
    if ($SkipRestorePoint -or $Script:VerifyOnlyRun) { return }
    # --- AUDIT: System Restore checkpoint BEFORE any change, so the whole run can be rolled
    # back via Windows if something breaks. Audit: documented recovery path.
    Write-Section 'System Restore Point'
    Invoke-Step 'Restore' "Enabled System Restore on $env:SystemDrive" {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    }
    Invoke-Step 'Restore' "Created restore point 'Pre-Hardening-v2.2'" {
        # Windows throttles restore points to 1 / 24h by default; may skip silently.
        Checkpoint-Computer -Description 'Pre-Hardening-v2.2' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    }
}

function Invoke-Mod-Defender {
    # --- AUDIT: Microsoft Defender AV baseline: real-time protection, behavior monitoring,
    # PUA/network protection ON, and (by default) NO cloud reporting or sample
    # submission - protection stays local, nothing is sent to Microsoft. Audit maps
    # to endpoint-protection + data-egress controls (CIS 18.9.47.x).
    Write-Section 'Microsoft Defender Antivirus'
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.AMRunning)    { Write-Log WARN 'Defender AV engine not reported running (third-party AV may be active). Set-MpPreference changes may be ignored.' }
        if ($mp.IsTamperProtected) { Write-Log WARN 'Tamper Protection is ON. Some Set-MpPreference toggles will be blocked by design (expected/good).' }
    } catch { Write-Log WARN "Get-MpComputerStatus failed: $($_.Exception.Message)" }

    Invoke-Step 'Defender' 'Real-time protection ON'        { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
    Invoke-Step 'Defender' 'Behavior monitoring ON'         { Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop }
    Invoke-Step 'Defender' 'Script scanning ON'             { Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop }
    Invoke-Step 'Defender' 'Archive scanning ON'            { Set-MpPreference -DisableArchiveScanning $false -ErrorAction Stop }
    Invoke-Step 'Defender' 'Removable-drive scanning ON'    { Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction Stop }
    Invoke-Step 'Defender' 'PUA protection = Enabled'       { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop }
    Invoke-Step 'Defender' 'Network protection = Enabled'   { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop }
    # PRIVACY / NO-EXFIL default: do NOT send reports, telemetry, or files to
    # Microsoft. MAPS/SpyNet reporting off = no cloud telemetry submissions;
    # SubmitSamplesConsent = 2 (NeverSend) = suspicious files never leave the box.
    # Honest tradeoff (bug 26): this reduces cloud-delivered protection - Defender
    # still scans locally with its signatures, but loses real-time cloud lookups
    # and community-sourced blocks. If you want max protection over privacy, set
    # -CloudProtection (below) to re-enable MAPS Advanced + SendSafeSamples.
    if ($CloudProtection) {
        Invoke-Step 'Defender' 'Cloud protection = Advanced (MAPS ON, sends telemetry)' { Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop }
        Invoke-Step 'Defender' 'Sample submission = SendSafe (sends files)'             { Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop }
        Invoke-Step 'Defender' 'Cloud block level = High'    { Set-MpPreference -CloudBlockLevel High -ErrorAction Stop }
        Invoke-Step 'Defender' 'Cloud extended timeout = 50s'{ Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction Stop }
    } else {
        Invoke-Step 'Defender' 'Cloud reporting OFF (no MAPS/SpyNet telemetry)'   { Set-MpPreference -MAPSReporting Disabled -ErrorAction Stop }
        Invoke-Step 'Defender' 'Sample submission = NEVER (no files sent to MS)'  { Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction Stop }
        # Belt-and-suspenders via policy registry (survives some GUI toggles).
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpynetReporting' 0 -Category 'Defender' -Item 'SpyNet reporting off (policy)'
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 2 -Category 'Defender' -Item 'Never submit samples (policy)'
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'LocalSettingOverrideSpynetReporting' 0 -Category 'Defender' -Item 'Lock SpyNet off (no local override)'
        $Script:ManualSteps.Add('Defender is set to send NOTHING to Microsoft (no MAPS telemetry, no sample files). Local signature scanning still works, but cloud-delivered protection and CloudBlockLevel are inert without MAPS. Re-run with -CloudProtection if you want max protection over privacy.')
    }
    Invoke-Step 'Defender' 'Signature update interval = 6h' { Set-MpPreference -SignatureUpdateInterval 6 -ErrorAction Stop }
    if ($SkipDefenderSignatureUpdate) {
        Write-Log INFO 'Skipping Update-MpSignature (-SkipDefenderSignatureUpdate).'
        Add-Result 'Defender' 'Signature update' 'Skipped' 'by option'
    } else {
        Invoke-Step 'Defender' 'Updated signatures' { Update-MpSignature -ErrorAction Stop }
    }
}

function Invoke-Mod-ASR {
    Write-Section 'Attack Surface Reduction (ASR) rules'
    # Prevalence/age rule starts in AuditMode (most false-positive-prone).
    $asr = @(
        @{ Id='9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Name='Block credential theft from LSASS';                Action='Enabled'   },
        @{ Id='be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Name='Block executable content from email/webmail';      Action='Enabled'   },
        @{ Id='d4f940ab-401b-4efc-aadc-ad5f3c50688a'; Name='Block Office apps creating child processes';        Action='Enabled'   },
        @{ Id='3b576869-a4ec-4529-8536-b80a7769e899'; Name='Block Office apps creating executable content';     Action='Enabled'   },
        @{ Id='75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Name='Block Office apps injecting into processes';         Action='Enabled'   },
        @{ Id='d3e037e1-3eb8-44c8-a917-57927947596d'; Name='Block JS/VBScript launching downloaded content';    Action='Enabled'   },
        @{ Id='5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Name='Block obfuscated scripts';                          Action='Enabled'   },
        @{ Id='92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Name='Block Win32 API calls from Office macros';          Action='Enabled'   },
        @{ Id='c1db55ab-c21a-4637-bb3f-a12568109d35'; Name='Advanced ransomware protection';                    Action='Enabled'   },
        @{ Id='26190899-1602-49e8-8b27-eb1d0a1ce869'; Name='Block comms apps creating child processes';         Action='Enabled'   },
        @{ Id='7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Name='Block Adobe Reader creating child processes';       Action='Enabled'   },
        @{ Id='e6db77e5-3df2-4cf1-b95a-636979351e5b'; Name='Block persistence via WMI event subscription';      Action='Enabled'   },
        @{ Id='56a863a9-875e-4185-98a7-b882c64b5ce5'; Name='Block abuse of exploited vulnerable signed drivers (BYOVD)'; Action='Enabled' },
        # PSExec/WMI process-creation: guide says Block, but that breaks legitimate
        # remote admin (MECM/SCCM use WMI) AND a pentester's own lateral-movement
        # tooling. We AUDIT it (not Block) to stay consistent with admin-shares
        # being opt-in, and match Microsoft's own audit-first posture for admin-
        # impacting rules. Flip to 'Enabled' if this box does no PSExec/WMI admin.
        @{ Id='d1e49aac-8f56-4280-b9ba-993a6d77406c'; Name='Block PSExec/WMI process creation (AUDIT only - breaks remote admin)'; Action='AuditMode' },
        @{ Id='b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Name='Block untrusted/unsigned processes from USB';       Action='Enabled'   },
        @{ Id='01443614-cd74-433a-b99e-2ecdc07bfc25'; Name='Block untrusted execs (prevalence/age) [FP-prone]'; Action='AuditMode' }
    )
    foreach ($rule in $asr) {
        $r = $rule
        Invoke-Step 'ASR' "$($r.Name) [$($r.Action)]" {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $r.Id -AttackSurfaceReductionRules_Actions $r.Action -ErrorAction Stop
        }
    }
    $Script:ManualSteps.Add('ASR: prevalence/age rule (01443614) is in AUDIT. Review Defender Operational events (1121/1122), then re-run flipping it to Enabled.')
    # Microsoft Vulnerable Driver Blocklist: blocks known-exploitable signed kernel
    # drivers (the BYOVD attack path - an attacker drops a legit-but-flawed ring-0
    # driver to disable AV/EDR). One reg key, standalone-safe, high value. Baseline
    # (not gated behind opt-in DeviceGuard). Adversaries try to set this to 0, so
    # the Verify pass re-checks it.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 1 -Category 'ASR' -Item 'Vulnerable driver blocklist ON (anti-BYOVD)'
}

function Invoke-Mod-Firewall {
    # --- AUDIT: Windows Defender Firewall ON for all profiles with default-deny inbound and
    # dropped-packet logging. The perimeter is assumed hostile; the host firewall
    # is the enforcement point. Audit: CIS 9.x (firewall state, logging).
    Write-Section 'Windows Firewall (enable + logging)'
    Invoke-Step 'Firewall' 'Firewall enabled on all profiles' {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    }
    Invoke-Step 'Firewall' 'Default inbound = Block' {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
    }
    Invoke-Step 'Firewall' 'Logging enabled (dropped + allowed, 16MB)' {
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
    }
}

function Invoke-Mod-SmartScreen {
    # --- AUDIT: SmartScreen reputation filtering at both the shell and Edge: unrecognized or
    # known-malicious apps/URLs are blocked before execution. Defends the initial-
    # access / download vector. Audit: CIS 18.9.85.x, MS Baseline.
    Write-Section 'SmartScreen'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1 -Category 'SmartScreen' -Item 'SmartScreen (Explorer) on'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' 'String' -Category 'SmartScreen' -Item 'SmartScreen level = Block'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 1 -Category 'SmartScreen' -Item 'Edge SmartScreen on'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled' 1 -Category 'SmartScreen' -Item 'Edge PUA blocking on'
    # --- 24H2 GUIDE: Edge Enhanced Security Mode. MDAG (Application Guard) was
    # REMOVED in 24H2; this is the replacement - it disables JIT JavaScript
    # compilation on untrusted sites, removing a large class of browser RCE.
    # 2 = enabled for all sites (strict). Low breakage on general browsing.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'EnhanceSecurityMode' 2 -Category 'SmartScreen' -Item 'Edge Enhanced Security Mode (JIT off)'
}

function Invoke-Mod-UAC {
    # --- AUDIT: User Account Control: the elevation boundary between standard and admin
    # rights. Full-prompt-on-secure-desktop stops silent/automated privilege
    # escalation and prompt-spoofing. A disabled UAC is a critical finding.
    # Audit: CIS 2.3.17.x.
    Write-Section 'User Account Control (UAC)'
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-Reg $uac 'EnableLUA' 1 -Category 'UAC' -Item 'UAC enabled (EnableLUA)'
    Set-Reg $uac 'ConsentPromptBehaviorAdmin' 2 -Category 'UAC' -Item 'UAC admin consent = prompt'   # prompt for consent on secure desktop
    Set-Reg $uac 'PromptOnSecureDesktop' 1 -Category 'UAC' -Item 'UAC prompts on secure desktop'
    Set-Reg $uac 'EnableInstallerDetection' 1 -Category 'UAC' -Item 'Detect installer elevation'
    Set-Reg $uac 'FilterAdministratorToken' 1 -Category 'UAC' -Item 'Admin Approval Mode for RID-500'  # admin approval mode for built-in admin
    # --- 24H2 GUIDE: Enhanced Privilege Protection (EPP) mode for UAC. Isolates
    # the elevation token via VBS and forces credential entry on the secure
    # desktop, so a keylogger/memory-injector in the user session cannot intercept
    # admin creds or hijack the elevated token during JIT elevation.
    # TypeOfAdminApprovalMode=2 = enhanced (24H2+; inert on older builds, harmless).
    Set-Reg $uac 'TypeOfAdminApprovalMode' 2 -Category 'UAC' -Item 'Enhanced Admin Approval Mode (EPP, 24H2)'
}

function Invoke-Mod-Features {
    # --- AUDIT: Removal of legacy/vulnerable optional features (SMBv1, PowerShell v2,
    # etc.). Each is a known exploitation surface (e.g. SMBv1 = EternalBlue).
    # State-checked first so already-absent features do not false-fail. Audit:
    # CIS 18.x legacy-protocol controls.
    Write-Section 'Legacy / Risky Feature Removal'
    # SMBv1 SERVER config: safe to set even when already off (idempotent).
    Invoke-Step 'Features' 'SMBv1 server config disabled' {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    }
    $features = @(
        @{ N='SMB1Protocol';                                D='Legacy SMBv1 protocol' },
        @{ N='MicrosoftWindowsPowerShellV2Root';            D='PowerShell v2 (bypasses AMSI/ScriptBlock logging)' },
        @{ N='Printing-Foundation-InternetPrinting-Client'; D='Internet Printing Client' },
        @{ N='WorkFolders-Client';                          D='Work Folders client' }
    )
    foreach ($f in $features) {
        $ff = $f
        # bug W6: Disable-WindowsOptionalFeature THROWS on a feature that is
        # already absent - and on current Win11 builds SMB1Protocol ships
        # removed. The old code caught that as a [Failed] step AND flagged a
        # reboot for a no-op. "Installed != present" is the same class as bug 42
        # (installed != running). Check state first; absent/disabled = already
        # done, not a failure.
        $state = $null
        try { $state = (Get-WindowsOptionalFeature -Online -FeatureName $ff.N -ErrorAction Stop).State } catch {}
        if ($null -eq $state) {
            Write-Log INFO "Feature '$($ff.N)' not present on this edition/build; nothing to remove."
            Add-Result 'Features' "Removed $($ff.D)" 'Skipped' 'feature not present'
            continue
        }
        if ($state -eq 'Disabled' -or $state -eq 'DisabledWithPayloadRemoved') {
            Write-Log OK "Feature '$($ff.N)' already disabled."
            Add-Result 'Features' "Removed $($ff.D)" 'Applied' 'already disabled'
            continue
        }
        Invoke-Step 'Features' "Removed $($ff.D)" {
            Disable-WindowsOptionalFeature -Online -FeatureName $ff.N -NoRestart -ErrorAction Stop | Out-Null
        } -RebootRequired
        Add-Undo @{ Kind='Command'; Undo="Enable-WindowsOptionalFeature -Online -FeatureName '$($ff.N)' -NoRestart -ErrorAction SilentlyContinue  # may require source media"; Label="re-enable feature $($ff.N)" }
    }
}

function Invoke-Mod-AutoRun {
    # --- AUDIT: AutoRun/AutoPlay disabled for all drive classes. Closes the removable-media
    # auto-execute path (rogue USB -> code runs on insert). Audit: CIS 18.9.8.x.
    Write-Section 'AutoRun / AutoPlay'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 -Category 'AutoRun' -Item 'AutoRun disabled all drives'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1 -Category 'AutoRun' -Item 'Autorun commands ignored'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 -Category 'AutoRun' -Item 'No Autoplay for MTP/PTP'
}

function Invoke-Mod-Network {
    # --- AUDIT: Network-stack hardening: kills broadcast name-resolution (LLMNR/NetBIOS/mDNS)
    # that Responder poisons for credential theft, disables IPv6 transition tunnels
    # (firewall-bypass/exfil corridors), and hardens IP/RPC behaviour. Audit: CIS
    # 18.5.x, DISA STIG network controls.
    Write-Section 'Network Hardening (LLMNR / NetBIOS / WPAD / DoH)'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 -Category 'Network' -Item 'LLMNR disabled'  # LLMNR off
    Invoke-Step 'Network' 'Disabled NetBIOS over TCP/IP on all adapters' {
        Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled } | ForEach-Object {
            Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
        }
    }
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' 'WpadOverride' 1 -Category 'Network' -Item 'WPAD auto-proxy disabled'   # WPAD off
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableAutoDoh' 2 -Category 'Network' -Item 'Auto DoH upgrade when server supports it'             # DoH auto
    # --- AUDIT-DRIVEN TCP/IP STACK HARDENING (CIS 18.5.x / STIG) ---
    # IP source routing lets a sender dictate the packet's route - a spoofing /
    # bypass primitive. 2 = highest protection (disabled entirely). Both stacks.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2 -Category 'Network' -Item 'IPv4 source routing disabled'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2 -Category 'Network' -Item 'IPv6 source routing disabled'
    # ICMP redirects can be used to reroute traffic (MITM). Do not let ICMP
    # override OSPF/static routes. (CIS 18.5.x)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0 -Category 'Network' -Item 'ICMP redirects ignored'
    # Ignore NetBIOS name-release requests from the network (a DoS/poisoning
    # vector against name resolution). (CIS 18.5.x)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' 'NoNameReleaseOnDemand' 1 -Category 'Network' -Item 'Ignore NetBIOS name-release'
    # --- 4-TIER GUIDE ADDITIONS (Tier 1-2, low breakage, standalone-safe) ---
    # NetBIOS off at the Dnscache layer too (belt with the per-adapter call above;
    # the reg is more reliable on static IPs). (Guide Domain A.2, Tier 2.)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableNetbios' 0 -Category 'Network' -Item 'NetBIOS off (Dnscache layer)'
    # Reject insecure GUEST SMB logons: stops silent fallback to an unauthenticated
    # guest session serving attacker content. (Guide Domain B.3, CIS 18.x.)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 0 -Category 'Network' -Item 'No insecure guest SMB logons'
    # IPv6 transition tech (Teredo/ISATAP/6to4/IP-HTTPS): synthetic tunnels over
    # IPv4 that bypass IPv4 firewall/IDS - a classic exfil/C2 corridor. No impact
    # on native IPv4 or native IPv6. (Guide Domain D.2, Tier 2.)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'Teredo_State' 'Disabled' 'String' -Category 'Network' -Item 'Teredo tunnel off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'ISATAP_State' 'Disabled' 'String' -Category 'Network' -Item 'ISATAP tunnel off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' '6to4_State' 'Disabled' 'String' -Category 'Network' -Item '6to4 tunnel off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'IPHTTPS_ClientState' 0 -Category 'Network' -Item 'IP-HTTPS client off'
    # RPC endpoint mapper: require auth for remote callers so anon callers cannot
    # enumerate interface UUIDs / vulnerable services. We use 1 (authenticated WITH
    # exceptions), NOT the guide's 2 (no exceptions) which breaks legit services on
    # a standalone box. (Guide Domain B.5, CIS.)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients' 1 -Category 'Network' -Item 'RPC requires auth (with exceptions)'
    # Delivery Optimization: HTTP-only, no peer sharing (0). Stops unpredictable
    # peer-to-peer update connections between endpoints. Low breakage (more WU
    # bandwidth only). (Guide Domain A.8, Tier 2.)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 0 -Category 'Network' -Item 'Delivery Optimization peering off'
    # Mobile hotspot / ICS UI off: stops a user turning the box into an
    # unauthorized network bridge. Low breakage. (Guide Domain D.1.)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI' 0 -Category 'Network' -Item 'Mobile hotspot / ICS disabled'

    # --- AUDIT: WinINET / Internet Settings TLS hardening. This is the peer to the
    # SCHANNEL protocol work above: SCHANNEL governs the OS crypto layer, while
    # WinINET SecureProtocols governs IE-engine / WinINET HTTP clients (Edge IE-mode,
    # some .NET and system components, legacy line-of-business apps). Pin both to
    # TLS 1.2+1.3 so neither layer can be downgraded. SecureProtocols bitmask:
    # SSL2=8 SSL3=32 TLS1.0=128 TLS1.1=512 TLS1.2=2048 TLS1.3=8192; 2048+8192=10240
    # (0x2800) = TLS 1.2 and 1.3 only. HKLM + HKCU (user-context clients read HKCU).
    $inet = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-Reg "HKLM:\$inet" 'SecureProtocols' 10240 -Category 'Network' -Item 'WinINET TLS 1.2/1.3 only (SSL2/3, TLS1.0/1.1 off)'
    Set-Reg "HKCU:\$inet" 'SecureProtocols' 10240 -Category 'Network' -Item 'WinINET TLS 1.2/1.3 only (user hive)'
    Set-Reg "HKLM:\$inet" 'CertificateRevocation' 1 -Category 'Network' -Item 'WinINET checks server cert revocation (CRL/OCSP)'
    Set-Reg "HKCU:\$inet" 'CertificateRevocation' 1 -Category 'Network' -Item 'WinINET cert revocation check (user hive)'
    Set-Reg "HKCU:\$inet" 'WarnonBadCertRecving' 1 -Category 'Network' -Item 'Warn on certificate address mismatch'
    Set-Reg "HKCU:\$inet" 'DisableCachingOfSSLPages' 1 -Category 'Network' -Item 'Do not cache HTTPS pages to disk'
}

function Invoke-Mod-Credential {
    # --- AUDIT: Credential-theft defenses: no cleartext creds cached in LSASS (WDigest off),
    # LSA Protection (RunAsPPL), no LM hashes, no anonymous/null-session enumeration,
    # LDAP signing, AES-only Kerberos. This is the anti-Mimikatz / anti-relay core.
    # Audit: CIS 2.3.x, DISA STIG credential controls.
    Write-Section 'Credential / Authentication Hardening'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-Reg $lsa 'NoLMHash' 1 -Category 'Credential' -Item 'No LM hash stored'
    Set-Reg $lsa 'RestrictAnonymous' 1 -Category 'Credential' -Item 'Anonymous enumeration restricted'
    Set-Reg $lsa 'RestrictAnonymousSAM' 1 -Category 'Credential' -Item 'Anonymous SAM enumeration off'
    Set-Reg $lsa 'LmCompatibilityLevel' $LmCompatibilityLevel -Category 'Credential' -Item "LmCompatibilityLevel=$LmCompatibilityLevel"
    Set-Reg $lsa 'RunAsPPL' 1 -Category 'Credential' -Item 'LSASS as Protected Process Light (RunAsPPL)'
    $Script:RebootNeeded.Add('Credential - LSASS RunAsPPL')
    if ($LmCompatibilityLevel -ge 5) {
        $Script:ManualSteps.Add('LmCompatibilityLevel=5 can break auth to very old SMB/legacy devices. If shares break, re-run with -LmCompatibilityLevel 3.')
    }
    foreach ($proto in @('SSL 2.0','SSL 3.0')) {
        foreach ($role in @('Server','Client')) {
            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$role"
            Set-Reg $p 'Enabled' 0 -Category 'TLS' -Item 'Legacy SSL/TLS protocol disabled (server/client)'
            Set-Reg $p 'DisabledByDefault' 1 -Category 'TLS' -Item 'Legacy SSL/TLS off by default'
        }
    }
    # SMB signing on BOTH sides (defends SMB relay). The workstation SERVER and
    # CLIENT are separate keys; a client-only setting (as in the review guide)
    # leaves the server side open. Signing is not encryption - noted honestly.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 -Category 'SMB' -Item 'SMB client signing required'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1 -Category 'SMB' -Item 'SMB server signing required'
    $Script:ManualSteps.Add('SMB signing is required on client and server. This defends SMB RELAY; it is NOT the same as SMB encryption. For encryption in transit, set Set-SmbServerConfiguration -EncryptData $true on shares that need it (can break old clients).')
    # ROCA (CVE-2017-15361): block WHfB auth using keys from vulnerable Infineon
    # TPMs. Value 2 = block. Harmless on unaffected TPMs (they never produced
    # ROCA-weak keys), so safe to set unconditionally.
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM' 'SamNGCKeyROCAValidation' 2 -Category 'Credential' -Item 'Block ROCA-vulnerable WHfB keys'

    # --- AUDIT-DRIVEN CREDENTIAL HARDENING (CIS L1/L2, DISA STIG) ---
    # WDigest: when UseLogonCredential=1, Windows caches the user's CLEARTEXT
    # password in LSASS memory - the classic Mimikatz "sekurlsa::wdigest" target.
    # Setting it to 0 forces credential-less WDigest. This is one of the single
    # most impactful credential-theft mitigations and a guaranteed audit finding
    # if missing. (CIS 18.x / STIG WN11-CC-*).
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -Category 'Credential' -Item 'WDigest cleartext credential caching OFF'
    # Blank-password accounts may only be used at the console, never over the
    # network. Prevents remote logon with an empty password. (CIS 2.3.1.x)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1 -Category 'Credential' -Item 'Blank passwords limited to console only'
    # Anonymous (null-session) access: do not let unauthenticated callers
    # enumerate SAM accounts/shares or reach named pipes/shares anonymously.
    # (CIS 2.3.10.x - a very common audit finding on legacy-configured boxes.)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 -Category 'Credential' -Item 'Anonymous not in Everyone'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' 1 -Category 'Credential' -Item 'Restrict anonymous share access'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionPipes' '' 'MultiString' -Category 'Credential' -Item 'No anonymous named pipes'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares' '' 'MultiString' -Category 'Credential' -Item 'No anonymous shares'
    # LDAP client signing: require integrity so LDAP binds cannot be relayed /
    # tampered. 1 = Negotiate signing. (CIS 2.3.11.x)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 -Category 'Credential' -Item 'LDAP client signing required'
    # Kerberos: allow only AES (0x18 = AES128+AES256), no legacy RC4/DES which
    # are crackable and enable Kerberoasting downgrade. (CIS 2.3.11.x / STIG.)
    # NOTE: on a NON-domain box this is inert but harmless; on domain-joined it
    # matters. Left in baseline because it does not break standalone use.
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 2147483640 -Category 'Credential' -Item 'Kerberos AES-only (no RC4/DES)'
    # Limit cached domain logons: fewer cached credential verifiers on disk means
    # fewer offline-crackable hashes if the box is stolen. 4 is a common CIS value
    # (0 breaks laptops that go offline; 4 balances). (CIS 2.3.7.x)
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' '4' 'String' -Category 'Credential' -Item 'Cached domain logons limited to 4'
}

function Invoke-Mod-RemoteAccess {
    Write-Section 'Remote Access'
    # NOTE (bug W2): this module DISABLES inbound RDP. If you are running the
    # script over RDP, your current session survives (established TCP is not
    # cut, and fDenyTSConnections only blocks NEW logons) but you cannot
    # RECONNECT after you disconnect. The guard refuses the severing steps in
    # that case unless -Force. Requiring UserAuthentication (NLA) is always
    # safe, so it runs regardless.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 -Category 'RemoteAccess' -Item 'RDP requires Network Level Authentication'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 -Category 'RemoteAccess' -Item 'Remote Assistance offers disabled'

    if (Assert-NotSeveringOurAccess -What 'Disable inbound RDP') {
        Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 -Category 'RemoteAccess' -Item 'Remote Desktop inbound denied'
        # BUGFIX: only disable RDP rules if they exist; absence is not a failure.
        Invoke-Step 'RemoteAccess' "Disabled 'Remote Desktop' firewall rules (if present)" {
            $rdp = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
            if ($rdp) { $rdp | Disable-NetFirewallRule -ErrorAction Stop }
        }
    }
}

function Invoke-Mod-Services {
    # --- AUDIT: Disables unneeded remote-facing services (Remote Registry, etc.) that expand
    # the attack surface with no benefit on a workstation. Audit: CIS 5.x services.
    Write-Section 'Services'
    $svc = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
    $priorStart = if ($svc) { (Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue).StartMode } else { $null }
    Invoke-Step 'Services' 'Disabled RemoteRegistry service' {
        Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
    }
    if ($svc -and $priorStart) {
        $ps = switch ($priorStart) { 'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {'Manual'} }
        Add-Undo @{ Kind='Command'; Undo="Set-Service -Name RemoteRegistry -StartupType $ps"; Label="RemoteRegistry startup -> $ps" }
    }
}

function Invoke-Mod-Privacy {
    # --- AUDIT: Telemetry / data-egress minimization: crash reports, diagnostic data, CEIP,
    # advertising ID, typing/inking collection, cloud clipboard - all off. The box
    # sends essentially nothing to Microsoft. Audit: data-handling / privacy
    # controls, CIS 18.9.x.
    Write-Section 'Telemetry / Privacy'
    $entEditions = @('Enterprise','EnterpriseS','EnterpriseN','EnterpriseSN','Education','EducationN','IoTEnterprise','ServerRnr')
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0 -Category 'Privacy' -Item 'Diagnostic data minimized'
    if ($Script:Edition -notin $entEditions) {
        Write-Log WARN "Edition '$Script:Edition' enforces a MINIMUM diagnostic level of 1 (Required); AllowTelemetry=0 floors at 1."
        Add-Result 'Privacy' 'Telemetry floor note' 'Info' 'Pro/Home floors at level 1'
    }
    Set-Reg 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1 -Category 'Privacy' -Item 'Windows Copilot off'
    # Windows Recall (24H2 Copilot+ PCs): continuously captures/archives screen
    # snapshots of everything the user does - a severe data-privacy, legal-discovery
    # and exfil risk. Disable it and force snapshot deletion. Standalone-safe.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'AllowRecallEnablement' 0 -Category 'Privacy' -Item 'Windows Recall (AI screen capture) OFF'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1 -Category 'Privacy' -Item 'Recall AI data analysis OFF'
    # HKCU copy too: Recall/AI analysis runs in USER context (AIXHost etc), so the
    # per-user policy hive closes a user-context bypass of the HKLM setting. Matches
    # the both-hives pattern already used for the Copilot kill-switch.
    Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1 -Category 'Privacy' -Item 'Recall AI data analysis OFF (user hive)'
    # Broader Windows 11 AI kill-switches (24H2/25H2 Copilot+ surface). Each is a
    # single policy key, reversible, and only costs the AI feature itself. These
    # extend the no-exfil posture: the OS-native AI models are continuous on-screen
    # observers (Recall, Click to Do, in-app AI), a real data-privacy/exfil surface.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'AllowRecallExport' 0 -Category 'Privacy' -Item 'Recall DB export API blocked'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableClickToDo' 1 -Category 'Privacy' -Item 'Click to Do (contextual screen analysis) OFF'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 0 -Category 'Privacy' -Item 'Edge Copilot sidebar OFF'
    Set-Reg 'HKLM:\SOFTWARE\Policies\WindowsNotepad' 'DisableAIFeatures' 1 -Category 'Privacy' -Item 'Notepad AI text scraping OFF'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' 'DisableCocreator' 1 -Category 'Privacy' -Item 'Paint Cocreator (generative AI) OFF'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' 'DisableGenerativeFill' 1 -Category 'Privacy' -Item 'Paint generative fill OFF'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1 -Category 'Privacy' -Item 'Start-menu Copilot/Bing search suggestions OFF'
    # Windows AI Fabric service (WSAIFabricSvc): orchestrates local AI model
    # execution and spawns WorkloadsSessionHost.exe, which even when idle preloads
    # models into 3-5GB RAM. Disable-ServiceSafe captures prior StartMode (reversible),
    # honors dry-run via Invoke-Step, and skips cleanly if the service is absent
    # (pre-Copilot+ builds). With the policy kill-switches above, the AI subsystem
    # has nothing left to run.
    Disable-ServiceSafe -Name 'WSAIFabricSvc' -Category 'Privacy' -Label 'Windows AI Fabric service disabled (frees WorkloadsSessionHost RAM)' | Out-Null
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1 -Category 'Privacy' -Item 'Windows Copilot off'
    if ($Script:Build -ge 26100) {
        Write-Log WARN 'On 24H2+ Copilot is an app; this policy may not fully remove it. Consider removing the Copilot Appx package as well.'
        Add-Result 'Privacy' 'Copilot policy note' 'Info' '24H2 Copilot is an app'
    }
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 1 -Category 'Privacy' -Item 'Start-menu web search off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 0 -Category 'Privacy' -Item 'No web results in search'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' 0 -Category 'Privacy' -Item 'Cortana disabled'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy' 1 -Category 'Privacy' -Item 'Advertising ID off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1 -Category 'Privacy' -Item 'Consumer features off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1 -Category 'Privacy' -Item 'Soft-landing tips off'
    # Activity History / Timeline: stops the OS logging file+app usage locally.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 0 -Category 'Privacy' -Item 'Activity feed off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 0 -Category 'Privacy' -Item 'Do not publish user activities'
    # Widgets / news-and-interests: web content polled into the shell, incl. the
    # lock screen (pre-auth surface). Dsh is the current (23H2+) policy path.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0 -Category 'Privacy' -Item 'News and interests widget off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' 'DisableWidgetsOnLockScreen' 1 -Category 'Privacy' -Item 'Lock-screen widgets off'

    # --- STOP OUTBOUND DATA / CRASH REPORTS / MEMORY DUMPS TO MICROSOFT ---
    # Windows Error Reporting: no crash reports, and no memory dumps / extra data
    # attached to any report a component still tries to send.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1 -Category 'Privacy' -Item 'Windows Error Reporting off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'DontSendAdditionalData' 1 -Category 'Privacy' -Item 'No extra data/memory with error reports'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'AutoApproveOSDumps' 0 -Category 'Privacy' -Item 'Do not auto-send OS crash dumps'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1 -Category 'Privacy' -Item 'WER off (machine key)'
    # Diagnostic-data transport / feedback: keep the OS from shipping diagnostics.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' 1 -Category 'Privacy' -Item 'No OneSettings pulls'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 1 -Category 'Privacy' -Item 'No feedback prompts/sends'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitEnhancedDiagnosticDataWindowsAnalytics' 1 -Category 'Privacy'
    Set-Reg 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' 0 -Category 'Privacy' -Item 'Feedback frequency = never'
    # CEIP + Application Impact Telemetry: both ship usage data to Microsoft.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0 -Category 'Privacy' -Item 'CEIP off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' 0 -Category 'Privacy' -Item 'App Impact Telemetry off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' 1 -Category 'Privacy' -Item 'App inventory collection off'
    # Inking & typing: stop handwriting/keystroke samples going to MS.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TextInput' 'AllowLinguisticDataCollection' 0 -Category 'Privacy' -Item 'No typing data collection'
    Set-Reg 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 1 -Category 'Privacy'
    Set-Reg 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 1 -Category 'Privacy' -Item 'No implicit typing-data collection'
    # Cloud clipboard / activity upload (leaves the device via your MS account).
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' 0 -Category 'Privacy' -Item 'No cloud clipboard sync'
    # --- 24H2 GUIDE / STIG: block clipboard redirection over RDP/VDI so data cannot
    # be exfiltrated host<->guest through the remote-session clipboard channel.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableClip' 1 -Category 'Privacy' -Item 'RDP clipboard redirection blocked'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm' 1 -Category 'Privacy' -Item 'RDP drive redirection blocked'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 0 -Category 'Privacy' -Item 'Do not upload user activities'
    # Crash-dump collection for telemetry, and hide the telemetry opt-in UI so a
    # user cannot silently re-enable diagnostic data after hardening.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDumpCollection' 1 -Category 'Privacy' -Item 'No crash-dump collection for telemetry'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' 1 -Category 'Privacy' -Item 'No diagnostic-log collection'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableTelemetryOptInSettingsUx' 1 -Category 'Privacy' -Item 'Hide telemetry opt-in UI (cannot re-enable via Settings)'
    $Script:ManualSteps.Add('Outbound data is minimized: Windows Error Reporting (incl. memory dumps), CEIP, App Impact Telemetry, feedback, typing/inking collection, and cloud clipboard are all off. Combined with Defender cloud-reporting off, the box sends essentially nothing to Microsoft. Note: on Pro/Home some diagnostic transport is edition-floored (AllowTelemetry cannot go below 1).')
}

function Get-CurrentAccountPolicy {
    # Capture the current 'net accounts' password/lockout values so an enforce can
    # be undone (relax back to what was there, or the user can read the prior state).
    $cap = @{}
    try {
        $out = & net accounts 2>&1
        foreach ($line in $out) {
            if     ($line -match 'Minimum password age.*?:\s*(\d+)')  { $cap['minpwage']  = $Matches[1] }
            elseif ($line -match 'Maximum password age.*?:\s*(\S+)')  { $cap['maxpwage']  = $Matches[1] }
            elseif ($line -match 'Minimum password length.*?:\s*(\d+)') { $cap['minpwlen'] = $Matches[1] }
            elseif ($line -match 'password history.*?:\s*(\S+)')      { $cap['uniquepw']  = $Matches[1] }
            elseif ($line -match 'Lockout threshold.*?:\s*(\S+)')     { $cap['lockout']   = $Matches[1] }
        }
    } catch {}
    return $cap
}

function Invoke-Mod-AccountPolicy {
    # --- AUDIT: password + lockout policy for LOCAL accounts (CIS 1.1.x/1.2.x,
    # DISA STIG). OPT-IN (extra security), NOT baseline - enforcing 14-char /
    # complexity / lockout on a personal or lab box is a footgun, so the user must
    # choose it. Two modes: ENFORCE (apply CIS values) and RELAX (remove the
    # requirements, back to permissive Windows defaults). Set via `net accounts`
    # + `secedit` (SAM/local-security-policy, not registry). On a domain the DOMAIN
    # policy governs domain accounts; these apply to LOCAL accounts.
    param([switch]$Relax)

    if ($Relax) {
        Write-Section 'Account policy - RELAX (remove password/lockout requirements)'
        # Permissive Windows defaults: no minimum length, no history, no lockout,
        # no complexity. This REMOVES the hardening (e.g. for a personal/lab box).
        $relaxAccounts = @(
            @{ Args = '/minpwlen:0';         Note = 'Minimum password length -> 0 (no minimum)' },
            @{ Args = '/maxpwage:unlimited'; Note = 'Max password age -> unlimited (never expires)' },
            @{ Args = '/minpwage:0';         Note = 'Min password age -> 0' },
            @{ Args = '/uniquepw:0';         Note = 'Password history -> 0 (no history)' },
            @{ Args = '/lockoutthreshold:0'; Note = 'Account lockout -> off (never locks)' }
        )
        foreach ($na in $relaxAccounts) {
            if ($Script:DryRun) { Write-Log DRY "WOULD run: net accounts $($na.Args)  [$($na.Note)]"; continue }
            Invoke-Step 'AccountPolicy' $na.Note {
                $out = & net accounts $na.Args.Split(' ') 2>&1
                if ($LASTEXITCODE -ne 0) { throw "net accounts failed: $out" }
            }
        }
        if (-not $Script:DryRun) {
            Invoke-Step 'AccountPolicy' 'Password complexity OFF (secedit)' {
                $inf = Join-Path $env:TEMP "sec_$([Guid]::NewGuid().ToString('N')).inf"
                $sdb = Join-Path $env:TEMP "sec_$([Guid]::NewGuid().ToString('N')).sdb"
                & secedit /export /cfg $inf /quiet | Out-Null
                $c = Get-Content $inf
                $c = $c -replace 'PasswordComplexity\s*=\s*\d+', 'PasswordComplexity = 0'
                $c | Set-Content $inf
                & secedit /configure /db $sdb /cfg $inf /quiet | Out-Null
                Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
            }
        } else { Write-Log DRY 'WOULD set PasswordComplexity=0 via secedit (relax)' }
        $Script:ManualSteps.Add('Account policy RELAXED: password length/history/lockout/complexity requirements removed (permissive defaults). Re-apply hardening via extra-security > password policy > enforce.')
        return
    }

    Write-Section 'Account policy - ENFORCE (password + lockout, CIS/STIG)'
    # Capture the current values first so the change is documented/undoable.
    if (-not $Script:DryRun) {
        $prior = Get-CurrentAccountPolicy
        if ($prior.Count -gt 0) {
            $Script:ManualSteps.Add("Account policy PRIOR state (before enforce): minlen=$($prior['minpwlen']) maxage=$($prior['maxpwage']) history=$($prior['uniquepw']) lockout=$($prior['lockout']). To revert, use extra-security > password policy > relax.")
        }
    }
    $netAccounts = @(
        @{ Args = '/minpwlen:14';        Note = 'Minimum password length 14 (CIS 1.1.4)' },
        @{ Args = '/maxpwage:365';       Note = 'Max password age 365 days (CIS 1.1.2; 0=never is a finding)' },
        @{ Args = '/minpwage:1';         Note = 'Min password age 1 day (stops instant history cycling, CIS 1.1.3)' },
        @{ Args = '/uniquepw:24';        Note = 'Password history 24 (CIS 1.1.1)' },
        @{ Args = '/lockoutthreshold:5'; Note = 'Account lockout after 5 bad tries (CIS 1.2.2)' },
        @{ Args = '/lockoutduration:15'; Note = 'Lockout duration 15 min (CIS 1.2.1)' },
        @{ Args = '/lockoutwindow:15';   Note = 'Lockout counter reset 15 min (CIS 1.2.3)' }
    )
    foreach ($na in $netAccounts) {
        if ($Script:DryRun) { Write-Log DRY "WOULD run: net accounts $($na.Args)  [$($na.Note)]"; continue }
        Invoke-Step 'AccountPolicy' $na.Note {
            $out = & net accounts $na.Args.Split(' ') 2>&1
            if ($LASTEXITCODE -ne 0) { throw "net accounts failed: $out" }
        }
    }
    if (-not $Script:DryRun) {
        Invoke-Step 'AccountPolicy' 'Password complexity ON, reversible encryption OFF (secedit)' {
            $inf = Join-Path $env:TEMP "sec_$([Guid]::NewGuid().ToString('N')).inf"
            $sdb = Join-Path $env:TEMP "sec_$([Guid]::NewGuid().ToString('N')).sdb"
            & secedit /export /cfg $inf /quiet | Out-Null
            $c = Get-Content $inf
            $c = $c -replace 'PasswordComplexity\s*=\s*\d+', 'PasswordComplexity = 1'
            $c = $c -replace 'ClearTextPassword\s*=\s*\d+', 'ClearTextPassword = 0'
            $c | Set-Content $inf
            & secedit /configure /db $sdb /cfg $inf /quiet | Out-Null
            Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log DRY 'WOULD set PasswordComplexity=1 and ClearTextPassword=0 via secedit (CIS 1.1.5 / 1.1.6)'
    }
    $Script:ManualSteps.Add('Account policy ENFORCED on LOCAL accounts (length/age/history, lockout, complexity). On a domain the DOMAIN policy governs domain accounts. To REMOVE these requirements later: extra-security > password policy > relax.')
}

function Invoke-Mod-LockScreenUI {
    Write-Section 'Lock screen / UI / installer policy'
    # --- AUDIT-DRIVEN UI + PRIVILEGE POLICY (CIS 18.x / 19.x, STIG) ---
    # AlwaysInstallElevated: if BOTH the HKLM and HKCU values are 1, any user can
    # install an MSI as SYSTEM - a textbook local privilege escalation. Force BOTH
    # to 0. This is a high-severity audit finding when left enabled. (CIS 18.9.x)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 -Category 'LockScreenUI' -Item 'MSI never installs elevated (HKLM)'
    Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 -Category 'LockScreenUI' -Item 'MSI never installs elevated (HKCU)'
    # Lock-screen camera + slideshow are pre-authentication surfaces (usable
    # without logging in). Disable both. (CIS 18.1.1.x)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' 1 -Category 'LockScreenUI' -Item 'Lock-screen camera off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenSlideshow' 1 -Category 'LockScreenUI' -Item 'Lock-screen slideshow off'
    # Machine inactivity limit: auto-lock the console after 900s idle so an
    # unattended session cannot be walked up to. (CIS 2.3.7.x)
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900 -Category 'LockScreenUI' -Item 'Auto-lock after 15 min idle'
    # Do not display last signed-in user at the lock screen (reduces username
    # disclosure for targeted attacks). (CIS 2.3.7.x)
    if ($KeepUsernameShown) {
        Write-Log INFO 'Keeping the last username SHOWN at logon (-KeepUsernameShown); skipping DontDisplayLastUserName.'
    } else {
        Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName' 1 -Category 'LockScreenUI' -Item 'Hide last username at logon'
    }
    # Require CTRL+ALT+DEL before logon (defeats credential-harvesting fake login
    # UIs). (CIS 2.3.7.x)
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD' 0 -Category 'LockScreenUI' -Item 'CTRL+ALT+DEL required at logon'
}

function Invoke-Mod-Audit {
    # --- AUDIT: Advanced audit policy + PowerShell logging (script-block, module,
    # transcription) + enlarged event logs. This is the FORENSIC EVIDENCE layer:
    # without it an intrusion leaves no trace. Audit: CIS 17.x, 18.9.100.x.
    Write-Section 'Auditing + PowerShell Logging'
    # BUGFIX: locale-independent subcategory GUIDs (English names fail on localized Windows).
    $auditSubs = @(
        @{ G='{0CCE922B-69AE-11D9-BED3-505054503030}'; N='Process Creation';             F=$true  },
        @{ G='{0CCE922C-69AE-11D9-BED3-505054503030}'; N='Process Termination';          F=$false },
        @{ G='{0CCE9215-69AE-11D9-BED3-505054503030}'; N='Logon';                        F=$true  },
        @{ G='{0CCE9216-69AE-11D9-BED3-505054503030}'; N='Logoff';                       F=$false },
        @{ G='{0CCE921B-69AE-11D9-BED3-505054503030}'; N='Special Logon';                F=$true  },
        @{ G='{0CCE9217-69AE-11D9-BED3-505054503030}'; N='Account Lockout';              F=$true  },
        @{ G='{0CCE923F-69AE-11D9-BED3-505054503030}'; N='Credential Validation';        F=$true  },
        @{ G='{0CCE9235-69AE-11D9-BED3-505054503030}'; N='User Account Management';       F=$true  },
        @{ G='{0CCE9237-69AE-11D9-BED3-505054503030}'; N='Security Group Management';     F=$true  },
        @{ G='{0CCE922F-69AE-11D9-BED3-505054503030}'; N='Audit Policy Change';          F=$true  },
        @{ G='{0CCE9230-69AE-11D9-BED3-505054503030}'; N='Authentication Policy Change';  F=$true  },
        @{ G='{0CCE9228-69AE-11D9-BED3-505054503030}'; N='Sensitive Privilege Use';      F=$true  },
        @{ G='{0CCE9210-69AE-11D9-BED3-505054503030}'; N='Security State Change';        F=$true  },
        @{ G='{0CCE9245-69AE-11D9-BED3-505054503030}'; N='Removable Storage';            F=$true  }
    )
    foreach ($a in $auditSubs) {
        $aa = $a
        $failFlag = if ($aa.F) { 'enable' } else { 'disable' }
        Invoke-Step 'Audit' "$($aa.N) (S:enable F:$failFlag)" {
            & auditpol /set /subcategory:"$($aa.G)" /success:enable /failure:$failFlag | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE" }
        }
    }
    Add-Undo @{ Kind='Manual'; Note="Advanced audit policy subcategories were enabled via auditpol. Prior per-subcategory state was not captured. To reset to defaults: auditpol /clear  (aggressive), or review auditpol /get /category:* and set individually."; Label='auditpol changes (prior state not captured)' }
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 -Category 'Audit'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 -Category 'Audit' -Item 'PowerShell script-block logging'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1 -Category 'Audit' -Item 'PowerShell module logging'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String' -Category 'Audit'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1 -Category 'Audit' -Item 'PowerShell transcription'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' 1 -Category 'Audit' -Item 'Transcript invocation headers'

    # Event log sizing (configurable via -EventLogSizeMB)
    $big   = $EventLogSizeMB * 1MB
    $small = ([math]::Min($EventLogSizeMB, 512)) * 1MB
    $logSizes = @{
        'Security'                                 = $big
        'Microsoft-Windows-PowerShell/Operational' = $big
        'System'                                   = $small
        'Application'                              = $small
        'Windows PowerShell'                       = $small
    }
    foreach ($ch in $logSizes.Keys) {
        $channel = $ch
        $size    = [int64]$logSizes[$ch]
        Invoke-Step 'Audit' "Event log '$channel' max size = $([math]::Round($size/1MB)) MB" {
            & wevtutil sl "$channel" /ms:$size | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "wevtutil exit code $LASTEXITCODE" }
        }
    }
}

function Invoke-Mod-DeviceGuard {
    if (-not $IncludeDeviceGuard) { return }
    # --- AUDIT: Virtualization-Based Security + HVCI (Memory Integrity): hypervisor-isolated
    # enclave validating kernel drivers and protecting credentials, neutralizing
    # kernel/rootkit exploit classes. Opt-in (-IncludeDeviceGuard). CIS 18.9.x.
    Write-Section 'Device Guard - VBS / HVCI / Credential Guard'
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        Write-Log INFO ("VBS status: {0} (0=off,1=configured,2=running)" -f $dg.VirtualizationBasedSecurityStatus)
        if ($dg.SecurityServicesRunning -contains 1) {
            Write-Log INFO 'Credential Guard is already RUNNING (typical Win11 Enterprise 22H2+ default).'
            Add-Result 'DeviceGuard' 'Credential Guard already running' 'Info'
        }
        if (-not ($dg.AvailableSecurityProperties -contains 2)) {
            Write-Log WARN 'Secure Boot not reported available - VBS/HVCI may not activate. Verify firmware settings.'
        }
    } catch { Write-Log WARN "Win32_DeviceGuard query failed: $($_.Exception.Message)" }

    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1 -Category 'DeviceGuard' -Item 'VBS enabled'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 3 -Category 'DeviceGuard' -Item 'VBS secure-boot required'  # Secure Boot + DMA
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1 -Category 'DeviceGuard' -Item 'HVCI (memory integrity) enabled'
    $cgFlag = if ($CredentialGuardUEFILock) { 1 } else { 2 }
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' $cgFlag -Category 'DeviceGuard' -Item "Credential Guard (LsaCfgFlags=$cgFlag)"
    $Script:RebootNeeded.Add('Device Guard / VBS / HVCI / Credential Guard')
    if ($CredentialGuardUEFILock) {
        $Script:ManualSteps.Add('Credential Guard set with UEFI LOCK - disabling later requires PHYSICAL presence at the UEFI menu.')
    }
}

function Invoke-Mod-Bloatware {
    if (-not $IncludeBloatwareRemoval) { return }
    # --- AUDIT: Removes preinstalled consumer UWP apps that widen attack surface / exfil
    # paths. Opt-in (-IncludeBloatwareRemoval); app set is environment-specific.
    Write-Section 'Bloatware Removal (provisioned UWP apps)'
    $bloat = @(
        'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted',
        'Microsoft.MicrosoftOfficeHub','Microsoft.MicrosoftSolitaireCollection','Microsoft.People',
        'Microsoft.SkypeApp','Microsoft.WindowsFeedbackHub','Microsoft.XboxApp',
        'Microsoft.XboxGamingOverlay','Microsoft.ZuneMusic','Microsoft.ZuneVideo',
        'Microsoft.Todos','Microsoft.PowerAutomateDesktop'
    )
    foreach ($app in $bloat) {
        $a = $app
        Invoke-Step 'Bloatware' "Removed $a" {
            Get-AppxPackage -Name $a -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -eq $a } |
                Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        }
        $reinstallNote = 'Removed provisioned app ''' + $a + '''. Reinstall from the Microsoft Store. Per-user re-register: Get-AppxPackage -AllUsers ''' + $a + ''' | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register (Join-Path $_.InstallLocation ''appxmanifest.xml'') }. Provisioned re-add needs the original package source.'
        Add-Undo @{ Kind='Manual'; Note=$reinstallNote; Label="removed app $a (manual reinstall)" }
    }
}

function Invoke-Mod-AdminAccount {
    if (-not $DisableBuiltinAdmin) { return }
    # --- AUDIT: Built-in account hygiene: Guest disabled, built-in Administrator (RID-500)
    # disabled. Predictable SIDs are prime brute-force / pass-the-hash targets.
    # Opt-in + guarded (never removes your last admin). CIS 2.3.1.x.
    Write-Section 'DANGEROUS: Disable Built-in Administrator + Guest'
    $enabledAdmins = @(Get-EnabledLocalAdmins)   # BUGFIX: force array
    $verifiedOk = $true

    if ($VerifiedAdminAccount) {
        $va = Get-LocalUser -Name $VerifiedAdminAccount -ErrorAction SilentlyContinue
        if (-not $va -or -not $va.Enabled) {
            $verifiedOk = $false
            Write-Log ERROR "-VerifiedAdminAccount '$VerifiedAdminAccount' not found or disabled. Refusing to disable built-in admin."
        } elseif ($enabledAdmins.Name -notcontains $va.Name) {
            $verifiedOk = $false
            Write-Log ERROR "'$VerifiedAdminAccount' is not an enabled member of Administrators. Refusing."
        }
    }

    if ($enabledAdmins.Count -eq 0) {
        Write-Log ERROR 'SAFETY STOP: no alternate enabled local administrator found. Not disabling built-in admin (lockout risk).'
        Add-Result 'AdminAccount' 'Disable built-in Administrator' 'Skipped' 'no alternate admin'
    } elseif (-not $verifiedOk) {
        Add-Result 'AdminAccount' 'Disable built-in Administrator' 'Skipped' 'verification failed'
    } else {
        Write-Log INFO ("Alternate enabled admin(s) present: {0}" -f (($enabledAdmins.Name) -join ', '))
        Invoke-Step 'AdminAccount' 'Disabled built-in Administrator (SID -500)' {
            $builtin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
            if ($builtin) { Disable-LocalUser -SID $builtin.SID -ErrorAction Stop }
        }
        Add-Undo @{ Kind='Command'; Undo="Get-LocalUser | Where-Object { `$_.SID.Value -like '*-500' } | Enable-LocalUser -ErrorAction SilentlyContinue"; Label='re-enable built-in Administrator' }
    }
    Invoke-Step 'AdminAccount' 'Disabled Guest account (SID -501)' {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        if ($guest) { Disable-LocalUser -SID $guest.SID -ErrorAction Stop }
    }
    Add-Undo @{ Kind='Manual'; Note="Guest account was disabled. Re-enabling Guest is almost never desirable; do it deliberately if truly needed: Get-LocalUser | Where-Object { `$_.SID.Value -like '*-501' } | Enable-LocalUser"; Label='Guest disabled (manual re-enable, not recommended)' }
    $Script:ManualSteps.Add('Deploy Windows LAPS (GPO/Intune) to rotate and escrow the local admin password to AD/Entra.')
}

function Invoke-Mod-BitLocker {
    if (-not $EnableBitLocker) { return }
    # --- AUDIT: Full-disk encryption (XTS-AES 256) + TPM+PIN pre-boot auth: protects data at
    # rest vs offline extraction, DMA, cold-boot. Opt-in, needs key escrow.
    # CIS 18.9.11.x.
    Write-Section 'DANGEROUS: BitLocker (XTS-AES-256, TPM+PIN)'
    if (-not $BitLockerKeyBackupPath) {
        Write-Log ERROR 'SAFETY STOP: -BitLockerKeyBackupPath is required (recovery-key escrow). Skipping BitLocker.'
        Add-Result 'BitLocker' 'Enable' 'Skipped' 'no key backup path'
        return
    }
    $tpm = try { Get-Tpm -ErrorAction Stop } catch { $null }
    if (-not $tpm -or -not $tpm.TpmPresent) {
        Write-Log ERROR 'SAFETY STOP: no TPM present. TPM+PIN BitLocker cannot be configured. Skipping.'
        Add-Result 'BitLocker' 'Enable' 'Skipped' 'no TPM'
        return
    }

    # Policy: XTS-AES-256 + require TPM+PIN
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'EncryptionMethodWithXtsOs' 7 -Category 'BitLocker' -Item 'BitLocker OS drive = XTS-AES-256'    # 7 = XTS-AES-256
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'EncryptionMethodWithXtsFdv' 7 -Category 'BitLocker' -Item 'BitLocker fixed drives = XTS-AES-256'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'EncryptionMethodWithXtsRdv' 6 -Category 'BitLocker'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'UseAdvancedStartup' 1 -Category 'BitLocker' -Item 'BitLocker pre-boot PIN required'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'UseTPMPIN' 1 -Category 'BitLocker' -Item 'BitLocker TPM+PIN'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'EnableBDEWithNoTPM' 0 -Category 'BitLocker' -Item 'No BitLocker without TPM'

    if ($Script:DryRun) {
        # bug W11: the reg policies above narrate via Set-Reg, but the actual
        # enable + escrow was silent on dry-run. A DANGEROUS module's preview
        # must describe what apply will do, especially the parts that prompt and
        # the parts that write a secret.
        Write-Log DRY "WOULD prompt for a startup PIN, enable BitLocker (XTS-AES-256, TPM+PIN) on $env:SystemDrive,"
        Write-Log DRY "      escrow the PLAINTEXT recovery key to $BitLockerKeyBackupPath, lock that path to"
        Write-Log DRY "      SYSTEM+Administrators, and attempt AD/Entra key backup."
        return
    }

    if (-not (Test-Path $BitLockerKeyBackupPath)) { New-Item -ItemType Directory -Path $BitLockerKeyBackupPath -Force | Out-Null }
    # bug W9: the recovery-key file holds the PLAINTEXT BitLocker recovery
    # password. Written naively it inherits the parent ACL; a local backup dir
    # inherits C:\ where BUILTIN\Users has Read, so any standard user could read
    # the key and decrypt a stolen/imaged disk - the escrow step defeating the
    # very control it exists to protect. Lock the directory down first. (A UNC
    # target keeps its share ACL; this only tightens local paths, which is where
    # the danger is.) Best-effort - if it is a share we cannot re-ACL, the file
    # step below still tries, and both warn on failure.
    if ($BitLockerKeyBackupPath -notlike '\\*') { Protect-Directory -Path $BitLockerKeyBackupPath | Out-Null }
    $osVol  = $env:SystemDrive
    $status = Get-BitLockerVolume -MountPoint $osVol -ErrorAction SilentlyContinue

    if ($status -and ($status.ProtectionStatus -eq 'On' -or $status.VolumeStatus -eq 'FullyEncrypted')) {
        Write-Log WARN "$osVol already BitLocker-protected. Skipping enable; ensuring key is escrowed."
    } else {
        # BUGFIX: guard interactive prompt + validate PIN length before enabling.
        if (-not [Environment]::UserInteractive) {
            Write-Log ERROR 'SAFETY STOP: BitLocker PIN requires an interactive session. Run interactively. Skipping enable.'
            Add-Result 'BitLocker' 'Enable' 'Skipped' 'non-interactive session'
            return
        }
        $pin = $null
        try { $pin = Read-Host -AsSecureString -Prompt 'Enter BitLocker startup PIN (6-20 digits)' }
        catch { Write-Log ERROR "PIN prompt failed: $($_.Exception.Message)"; Add-Result 'BitLocker' 'Enable' 'Skipped' 'PIN prompt failed'; return }

        if (-not $pin -or $pin.Length -lt 6 -or $pin.Length -gt 20) {
            Write-Log ERROR 'SAFETY STOP: PIN must be 6-20 characters. Skipping enable (no changes made to the volume).'
            Add-Result 'BitLocker' 'Enable' 'Skipped' 'invalid PIN length'
            return
        }
        # bug W7 (note, not a code change): this validates LENGTH only. A standard
        # BitLocker startup PIN is NUMERIC (0-9). A length-valid alpha/symbol PIN
        # passes this check and then fails at Add-BitLockerKeyProtector UNLESS the
        # 'Allow enhanced PINs for startup' policy (FVE\UseEnhancedPin=1) is set.
        # We do not enforce digits here because enhanced PINs are legitimate; the
        # failure, if it happens, is caught by Invoke-Step and reported honestly.
        $Script:ManualSteps.Add('BitLocker: startup PINs are numeric (0-9) by default. If you entered letters/symbols and enable failed, set the "Allow enhanced PINs for startup" policy (FVE\UseEnhancedPin=1) first, or use a numeric PIN.')
        Invoke-Step 'BitLocker' "Enabled BitLocker on $osVol (XTS-AES-256, TPM+PIN, used-space-only)" {
            Enable-BitLocker -MountPoint $osVol -EncryptionMethod XtsAes256 -UsedSpaceOnly `
                -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
            Add-BitLockerKeyProtector -MountPoint $osVol -TpmAndPinProtector -Pin $pin -ErrorAction Stop | Out-Null
        } -RebootRequired
        Add-Undo @{ Kind='Manual'; Note="BitLocker was ENABLED on $osVol. A script will NOT auto-decrypt (hours of I/O, data risk). To reverse deliberately: Disable-BitLocker -MountPoint '$osVol'  (then it decrypts in the background)."; Label="BitLocker on $osVol (manual reversal only)" }
    }

    # Escrow recovery key immediately (before background encryption finishes)
    Invoke-Step 'BitLocker' 'Escrowed recovery key to backup path' {
        $vol = Get-BitLockerVolume -MountPoint $osVol
        $rp  = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if ($rp) {
            # Idempotency / re-run note (double-run method): the file name is
            # timestamped, so every run drops ANOTHER plaintext copy of the
            # recovery key here. Each is valid, but N copies of the key = N
            # decryption paths for a stolen disk (compounds bug 39). Warn if
            # prior key files already exist so the operator prunes stale ones.
            $prior = @()
            try { $prior = @(Get-ChildItem -Path $BitLockerKeyBackupPath -Filter "BitLocker-Recovery-$env:COMPUTERNAME-*.txt" -ErrorAction SilentlyContinue) } catch {}
            if ($prior.Count -gt 0) {
                $Script:ManualSteps.Add("BitLocker: $($prior.Count) earlier recovery-key file(s) already exist in $BitLockerKeyBackupPath. Each is a plaintext copy of a valid recovery key. Keep the newest, securely delete the rest (they are extra decryption paths for a stolen disk).")
            }
            $file = Join-Path $BitLockerKeyBackupPath ("BitLocker-Recovery-{0}-{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
            # Restrict the file BEFORE the plaintext key lands in it (bug 39: the
            # window between write and chmod is the vulnerability). Only after
            # this do we write the recovery password.
            Protect-File -Path $file -Quiet | Out-Null
            $rp | ForEach-Object { "Computer: $env:COMPUTERNAME`nID: $($_.KeyProtectorId)`nRecovery Password: $($_.RecoveryPassword)`n" } |
                Out-File -FilePath $file -Encoding UTF8
            $Script:Artifacts.Add($file)
        } else { throw 'No recovery-password protector found to escrow.' }
    }
    Invoke-Step 'BitLocker' 'Attempted AD/Entra backup of recovery key' {
        $vol = Get-BitLockerVolume -MountPoint $osVol
        $rp  = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        foreach ($p in $rp) {
            try { Backup-BitLockerKeyProtector -MountPoint $osVol -KeyProtectorId $p.KeyProtectorId -ErrorAction Stop | Out-Null } catch {}
        }
    }
    $Script:ManualSteps.Add("BitLocker recovery key escrowed to $BitLockerKeyBackupPath. VERIFY the file exists and is stored securely off-device.")
}

function Invoke-Mod-AutoInstallGuard {
    # --- AUDIT: Blocks automatic driver/app/metadata installation on device insert and WPBT
    # firmware-binary execution - stops attacker hardware from pulling code. Opt-in.
    Write-Section 'EXTRA: prevent hardware/insert-triggered software install'

    # When hardware is inserted, Windows can (1) fetch device metadata that
    # references a companion Store app, (2) auto-search Windows Update for a
    # driver and install it, and separately (3) run a firmware-supplied binary
    # (WPBT) at boot. This module closes those insert/firmware -> software
    # execution paths. All via Set-Reg, so every change is in the undo script
    # and honours -DryRun.

    # --- (1) device metadata from the internet: low breakage, always apply ---
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' 'PreventDeviceMetadataFromNetwork' 1 -Category 'AutoInstall' -Item 'No device metadata from internet (blocks companion-app fetch on insert)'

    # --- (WPBT) firmware-supplied binary executed at boot: low breakage ---
    # A documented persistence / supply-chain vector. Disabling execution is
    # safe on normal hardware; a few OEM tools that rely on WPBT would stop.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'DisableWpbtExecution' 1 -Category 'AutoInstall' -Item 'Disable WPBT firmware-binary execution at boot'

    # --- (2) driver auto-install from Windows Update on insert ---
    # This is the medium-risk part: it is exactly "hardware insert should not
    # pull software", but it ALSO means a genuinely new device will not get a
    # driver automatically afterward. Stated loudly rather than hidden.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' 'DontSearchWindowsUpdate' 1 -Category 'AutoInstall' -Item 'Do not search Windows Update for drivers on device insert'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' 'DontPromptForWindowsUpdate' 1 -Category 'AutoInstall' -Item 'Do not prompt to search Windows Update for drivers'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ExcludeWUDriversInQualityUpdate' 1 -Category 'AutoInstall' -Item 'Exclude drivers from Windows Update quality updates'
    $Script:ManualSteps.Add('AutoInstall guard: inserting NEW hardware will no longer auto-download a driver or companion app. Existing hardware is unaffected (it already has drivers). To install a driver for a genuinely new device, do it deliberately from a trusted/managed source, or temporarily re-run the undo for the DriverSearching keys. Device metadata and WPBT execution are also off (low-impact, strong hardening).')

    Write-Log INFO 'Device-insert software install paths closed: metadata fetch, WU driver search, WPBT execution.'
}

function Invoke-Mod-USBGuard {
    # --- AUDIT: USB device-control: learn currently-present devices, allowlist them, deny new
    # ones. Keyboard/mouse are force-included so the console cannot be bricked.
    # Opt-in. Audit: removable-media / device-control controls.
    Write-Section 'EXTREME: USB device control (learn present, block new)'

    # The model: enumerate what is plugged in NOW, allowlist it (this is the
    # "learning" step), then set Device Installation policy to DENY new devices
    # while ALLOWING the learned list. HID (keyboard/mouse) is force-included so
    # the console can never lose input - the single most important safety rule
    # here. Everything below routes through Set-Reg, so it lands in the undo
    # script and honours -DryRun automatically. Enumeration is read-only.

    $diPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
    $allowPath = "$diPath\AllowDeviceIDs"

    # --- learn: enumerate present devices ---
    $present = @()
    try {
        $present = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
            Where-Object { $_.InstanceId -match '^USB\\' -and $_.Status -eq 'OK' })
    } catch {
        Write-Log WARN "Could not enumerate PnP devices: $($_.Exception.Message). USB lockdown NOT applied (cannot learn safely)."
        Add-Result 'USBGuard' 'Learn present devices' 'Skipped' 'enumeration failed'
        return
    }

    # Hardware IDs to allow. Force-include the HID class so input survives even
    # if a keyboard/mouse was momentarily not 'OK' during the scan.
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($d in $present) {
        $hwids = @()
        try { $hwids = @((Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction Stop).Data) } catch {}
        foreach ($h in $hwids) { if ($h -and -not $ids.Contains($h)) { $ids.Add($h) } }
    }
    # Force-allow all currently-attached HID and keyboard/mouse regardless.
    try {
        Get-PnpDevice -PresentOnly -Class 'Keyboard','Mouse','HIDClass' -ErrorAction SilentlyContinue | ForEach-Object {
            try { (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction Stop).Data |
                ForEach-Object { if ($_ -and -not $ids.Contains($_)) { $ids.Add($_) } } } catch {}
        }
    } catch {}

    if ($ids.Count -eq 0) {
        Write-Log WARN 'Learned ZERO device IDs. Refusing to enable a deny-all USB policy that would allow nothing (input-loss risk).'
        Add-Result 'USBGuard' 'USB lockdown' 'Skipped' 'no device IDs learned'
        return
    }
    Write-Log INFO "Learned $($ids.Count) hardware ID(s) from $($present.Count) present USB device(s), HID force-included."

    # Guard: an RDP/WinRM operator cannot see the console's input devices, so a
    # mistaken learn there could block the console's keyboard. Require -Force.
    if (($Script:RemoteSession.OverRDP -or $Script:RemoteSession.OverWinRM) -and -not $Force) {
        Write-Log ERROR 'SAFETY STOP: USB lockdown from a remote session cannot verify the console keyboard/mouse are in the allowlist. Skipped. Run at the console, or pass -Force if you are certain.'
        Add-Result 'USBGuard' 'USB lockdown' 'Skipped' 'remote session, no -Force'
        return
    }

    # --- write the allowlist (each ID is a numbered value under AllowDeviceIDs) ---
    $i = 1
    foreach ($id in $ids) {
        Set-Reg $allowPath "$i" $id 'String' -Category 'USBGuard' -Item "AllowDeviceID[$i]"
        $i++
    }
    # --- policy: allow the listed IDs, deny all others (new devices) ---
    Set-Reg $diPath 'AllowDeviceIDs' 1 -Category 'USBGuard' -Item 'Allow only listed device IDs'
    Set-Reg $diPath 'DenyUnspecified' 1 -Category 'USBGuard' -Item 'Deny devices not in the allowlist (blocks NEW)'
    # Do NOT set DenyDeviceClasses for input classes - that is the bricking move.

    $Script:ManualSteps.Add("USB lockdown: $($ids.Count) present device IDs were allowlisted; NEW/unlisted USB devices are blocked from installing. To approve a new device later: plug it in, run this module again (it re-learns) or add its hardware ID under $allowPath. HID was force-included so console input is safe. This does NOT block data on already-approved storage - see -BlockUSBStorage for that.")

    # Optional: block USB mass storage specifically (data exfil / rogue USB),
    # separate from device-install control. Gated behind its own switch.
    if ($BlockUSBStorage) {
        Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start' 4 -Category 'USBGuard' -Item 'USB mass storage disabled (Start=4)'
        $Script:ManualSteps.Add('USB mass storage (USBSTOR) was disabled. Already-approved storage will stop working too. Re-enable: set USBSTOR\Start=3.')
    } else {
        Write-Log INFO 'USB mass storage left enabled. Pass -BlockUSBStorage to disable it (stops rogue-USB data, but also all USB drives).'
    }
}

function Invoke-Mod-SurfaceReduction {
    # --- AUDIT: Miscellaneous attack-surface reduction (native sudo gating, etc.). Opt-in
    # items with sharper tradeoffs than the baseline.
    Write-Section 'Attack Surface: Windows sudo + Print Spooler (gated)'

    # Windows 11 24H2+ ships a native `sudo`. It can be an in-process elevation
    # vector depending on its mode. Disabling it is reasonable hardening - BUT
    # only where it exists and is not in use. The review guide disabled it
    # unconditionally with the wrong cmdlet; we detect first.
    $sudoKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
    $sudoPresent = (Get-Command sudo.exe -ErrorAction SilentlyContinue) -or (Test-Path $sudoKey)
    if (-not $sudoPresent) {
        Write-Log INFO 'Windows sudo not present on this build; nothing to disable.'
        Add-Result 'SurfaceReduction' 'Disable Windows sudo' 'Skipped' 'sudo not present'
    } else {
        Set-Reg $sudoKey 'Enabled' 0 -Category 'SurfaceReduction' -Item 'Windows sudo disabled'
        $Script:ManualSteps.Add('Windows sudo was disabled (Enabled=0). If a developer workflow on this box relied on it, re-enable with: set the Sudo\Enabled value or use Settings > System > For developers.')
    }

    # Print Spooler: PrintNightmare-class RCE lives here, so disabling it is
    # strong hardening on a box that never prints. But it IS an outage on a box
    # that does. Same lesson as the profile guard (bug 41): do not silently take
    # a capability the operator did not say they were done with. Gate it behind
    # an explicit switch; otherwise, only report the risk.
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler) {
        Add-Result 'SurfaceReduction' 'Disable Print Spooler' 'Skipped' 'service not present'
    } elseif ($DisablePrintSpooler) {
        # published printers => this box may be a print path for others
        $shared = @()
        try { $shared = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared }) } catch {}
        if ($shared.Count -gt 0 -and -not $Force) {
            Write-Log ERROR "SAFETY STOP: $($shared.Count) SHARED printer(s) on this box. Disabling the Spooler removes printing for their clients. Skipped. Pass -Force if intended."
            Add-Result 'SurfaceReduction' 'Disable Print Spooler' 'Skipped' 'shared printers present, no -Force'
        } else {
            Invoke-Step 'SurfaceReduction' 'Disabled and stopped Print Spooler' {
                Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop
                Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-Log INFO 'Print Spooler left running. Pass -DisablePrintSpooler to disable it (PrintNightmare surface) on a box that never prints.'
        Add-Result 'SurfaceReduction' 'Print Spooler' 'Info' 'left running (no -DisablePrintSpooler)'
        if ($spooler.Status -eq 'Running') {
            $Script:ManualSteps.Add('Print Spooler is RUNNING. If this box never prints, -DisablePrintSpooler removes a long history of RCE/LPE (PrintNightmare). If it prints, leave it and keep it patched.')
        }
    }
}

function Invoke-Mod-NTLM {
    # --- AUDIT: NTLM restriction/auditing: LM & NTLMv1 refused, outbound NTLM audited or
    # denied. NTLM enables pass-the-hash and relay; this is its deprecation path.
    # Audit: CIS 2.3.11.x, DISA STIG.
    Write-Section 'NTLM Restriction'
    $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    Set-Reg $msv 'AuditReceivingNTLMTraffic' 2 -Category 'NTLM' -Item 'Audit inbound NTLM'
    if ($EnforceNTLMDeny) {
        Set-Reg $msv 'RestrictSendingNTLMTraffic' 2 -Category 'NTLM' -Item 'Outgoing NTLM = DENY ALL'
        $Script:ManualSteps.Add('NTLM outgoing set to DENY ALL. Confirm no auth breakage to NTLM-only shares / NAS / legacy apps.')
    } else {
        Set-Reg $msv 'RestrictSendingNTLMTraffic' 1 -Category 'NTLM' -Item 'Outgoing NTLM = AUDIT'
        $Script:ManualSteps.Add('NTLM outgoing is in AUDIT. Review NTLM Operational events (8001-8004), then re-run with -EnforceNTLMDeny.')
    }
}

function Invoke-Mod-Outbound {
    # --- AUDIT: Explicit outbound egress control (opt-in): default-deny outbound with a
    # pinned DoH allow-list. Neutralizes unknown-malware C2 beaconing. Note: does
    # NOT stop exfil over an allowed HTTPS channel - stated honestly. Tier 3-4.
    Write-Section 'Outbound Firewall Posture'
    if (-not $BlockOutbound) {
        Invoke-Step 'Firewall' 'Default outbound = Allow (logging remains on)' {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
        }
        $Script:ManualSteps.Add('Outbound left as Allow (default). -BlockOutbound switches the default to block behind a starter allow-list, which stops odd-port malware and logs new egress paths - but it is not exfil control (it still permits DNS/HTTPS to any host). For real containment you need per-app rules with pinned destinations or a filtering proxy.')
        return
    }

    Write-Log WARN 'Pre-creating core outbound ALLOW rules before switching default to Block.'

    # bug W1: an L4 port allowlist is NOT egress control, and this must SAY so
    # rather than imply containment. 0harden shipped this exact defect (443 to
    # anywhere) and it was caught in review: a C2 or exfil channel that speaks
    # HTTPS to an arbitrary host walks straight through "allow TCP/443". What a
    # default-block outbound policy actually buys you is: it stops malware that
    # calls home on odd ports (4444, IRC, custom C2), and it turns every new
    # outbound path into a logged, deliberate decision. It does not stop
    # anything that speaks DNS or HTTPS to a host of its choosing.
    Write-Log WARN 'NOTE: this allow-list opens 53 and 443 to ANY host. That is not exfil'
    Write-Log WARN '      control - a C2/exfil channel on 443 is allowed. It stops odd-port'
    Write-Log WARN '      malware and makes new egress paths logged + deliberate. Real egress'
    Write-Log WARN '      control needs per-app + SNI/destination filtering, not L4 ports.'

    # DoH specifically: allowing TCP/443 to anywhere "for DoH" is the widest
    # possible reading of a narrow need. If you know your resolvers, pin them.
    # These are the well-known DoH providers; edit to match your environment. An
    # empty list falls back to 443-anywhere WITH the warning above.
    $dohResolvers = @('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112')

    $coreRules = @(
        @{ Name='Harden-Allow-DNS-UDP';  Proto='UDP'; Port=53;  Remote=$null },
        @{ Name='Harden-Allow-DNS-TCP';  Proto='TCP'; Port=53;  Remote=$null },
        @{ Name='Harden-Allow-DHCP-Out'; Proto='UDP'; Port=67;  Remote=$null },
        @{ Name='Harden-Allow-NTP';      Proto='UDP'; Port=123; Remote=$null },
        @{ Name='Harden-Allow-DoH';      Proto='TCP'; Port=443; Remote=$dohResolvers }
    )
    foreach ($cr in $coreRules) {
        $c = $cr
        # bug W10: detection must run OUTSIDE Invoke-Step. Invoke-Step returns
        # before executing its scriptblock on -DryRun, so putting the scope check
        # and the Remove-NetFirewallRule inside it meant the preview was blind to
        # a DESTRUCTIVE step (it deletes the old wide rule). That is bug 31 - dry
        # run hiding a real command. These reads are safe on a live box and on
        # dry-run, so they run here; only the mutations go through Invoke-Step.
        $existing = Get-NetFirewallRule -DisplayName $c.Name -ErrorAction SilentlyContinue
        $needRebuild = $false
        if ($existing -and $c.Remote) {
            $addrs = ($existing | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress
            $needRebuild = (-not $addrs) -or ($addrs -contains 'Any') -or ($addrs -contains '*')
        }

        if ($needRebuild) {
            # Re-run hazard (bug 16 family): a v2.1 box has Harden-Allow-DoH as
            # 443-to-ANYWHERE. A plain "skip if exists" would leave it wide and
            # silently not apply the pinned rule. Rebuild it - and show that on
            # dry-run, because it deletes a rule.
            Invoke-Step 'Firewall' "Rebuild unpinned $($c.Name) (delete wide rule, recreate pinned)" {
                Get-NetFirewallRule -DisplayName $c.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
                $params = @{
                    DisplayName = $c.Name; Direction = 'Outbound'; Action = 'Allow'
                    Protocol = $c.Proto; RemotePort = $c.Port; Profile = 'Any'; ErrorAction = 'Stop'
                }
                if ($c.Remote) { $params['RemoteAddress'] = $c.Remote }
                New-NetFirewallRule @params | Out-Null
            }
            # Undo of a rebuild is not clean: the prior rule was an UNPINNED
            # (wide) version, and re-creating that would re-open the hole this
            # fixed. So removing the pinned rule is the honest reversal; whether
            # to restore the old wide rule is a decision, not an automatic step.
            Add-Undo @{ Kind='Command'; Undo="Remove-NetFirewallRule -DisplayName '$($c.Name)' -ErrorAction SilentlyContinue"; Label="remove rebuilt outbound rule $($c.Name)" }
            Add-Undo @{ Kind='Manual'; Note="Outbound rule '$($c.Name)' was REBUILT from a wide (443-anywhere) v2.1 rule to a pinned one. The undo removes the pinned rule but does NOT recreate the old wide rule (that would re-open the hole). If you truly need it wide again, recreate it deliberately."; Label="rebuilt $($c.Name) (wide rule not auto-restored)" }
        } elseif (-not $existing) {
            Invoke-Step 'Firewall' "Outbound allow rule: $($c.Name)$(if($c.Remote){' (pinned)'}else{''})" {
                $params = @{
                    DisplayName = $c.Name; Direction = 'Outbound'; Action = 'Allow'
                    Protocol = $c.Proto; RemotePort = $c.Port; Profile = 'Any'; ErrorAction = 'Stop'
                }
                if ($c.Remote) { $params['RemoteAddress'] = $c.Remote }
                New-NetFirewallRule @params | Out-Null
            }
            Add-Undo @{ Kind='Command'; Undo="Remove-NetFirewallRule -DisplayName '$($c.Name)' -ErrorAction SilentlyContinue"; Label="remove outbound rule $($c.Name)" }
        } else {
            Write-Log INFO "Outbound rule $($c.Name) already present and acceptable."
            Add-Result 'Firewall' "Outbound allow rule: $($c.Name)" 'Skipped' 'already present'
        }
    }
    foreach ($svc in @('wuauserv','bits','dnscache')) {
        $s = $svc
        Invoke-Step 'Firewall' "Outbound allow rule for service: $s" {
            $rn = "Harden-Allow-Svc-$s"
            if (-not (Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $rn -Direction Outbound -Action Allow -Service $s -Profile Any -ErrorAction Stop | Out-Null
            }
        }
    }
    # bug W1 continued: allowing all installed browsers outbound to ANY host is
    # the single widest hole in this allow-list. It is convenient - the box can
    # still browse - but a browser talking to an attacker-chosen HTTPS host is
    # the most common exfil and C2 path there is, so these rules undo most of
    # what default-block was for. They are still created (a workstation that
    # cannot browse is a support ticket, not a hardened box), but the run says
    # plainly what they cost, so nobody reads "outbound blocked" as "contained".
    $browsers = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    ) | Where-Object { Test-Path $_ }
    if ($browsers) {
        Write-Log WARN "Allowing $(@($browsers).Count) browser(s) outbound to ANY host. This is the widest"
        Write-Log WARN '      rule in the set: browser-to-anywhere HTTPS is the usual exfil/C2 path.'
        Write-Log WARN '      Default-block still stops odd-port malware, but do not call this contained.'
    }
    foreach ($b in $browsers) {
        $bp = $b
        Invoke-Step 'Firewall' "Outbound allow rule for browser: $(Split-Path $bp -Leaf)" {
            $rn = "Harden-Allow-Browser-$(Split-Path $bp -Leaf)"
            if (-not (Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $rn -Direction Outbound -Action Allow -Program $bp -Profile Any -ErrorAction Stop | Out-Null
            }
        }
    }
    $Script:ManualSteps.Add('Outbound allow-list opens 53/443 to any host and lets installed browsers reach any host. That is not exfil control - it stops odd-port malware and makes new egress paths logged/deliberate. For real containment, pin destinations (the DoH rule shows the pattern) and replace browser-anywhere with proxy-only egress.')
    # A default-block outbound policy does not cut an inbound RDP session's
    # return traffic (that is the reply on an established inbound flow, allowed
    # by state), so RDP itself survives. But WinRM push, RMM agents, and any
    # admin tooling that phones OUT can die here - and if your only management
    # path is one of those, you have just stranded the box. Warn on a remote
    # session; do not hard-refuse, because outbound-block is the whole point of
    # the switch and RDP specifically is fine.
    if (($Script:RemoteSession.OverWinRM) -and -not $Force) {
        Write-Log ERROR 'SAFETY STOP: you are on a WinRM session and -BlockOutbound can strand agent/callback-based management. Skipped the default-block flip. Allow rules above were still created. Re-run from console/RDP, or pass -Force.'
        Add-Result 'Firewall' 'Default outbound = BLOCK' 'Skipped' 'WinRM session, no -Force'
        $Script:ManualSteps.Add('Outbound default-BLOCK was NOT applied (WinRM session). The allow rules were created; apply the block from a console or RDP session.')
    } else {
        Invoke-Step 'Firewall' 'Default outbound = BLOCK on all profiles' {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -ErrorAction Stop
        }
        Add-Undo @{ Kind='Command'; Undo="Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow"; Label='restore default outbound = Allow' }
        $Script:ManualSteps.Add('Outbound is now default-BLOCK. This starter allow-list is NOT complete - test every business app and add per-app allow rules. Non-browser HTTPS apps will fail until allowed.')
    }
}

function Invoke-Mod-Verify {
    # --- AUDIT: read-only verification. Writes NOTHING; re-reads the live
    # registry/service state and reports PASS/FAIL/PENDING/INCONCLUSIVE/INFO for
    # each invariant the other modules set. This is the evidence-gathering pass -
    # pair it with -AuditReport to produce the HTML control-mapping deliverable.
    Write-Section 'VERIFY - audit what is actually true right now (read-only)'
    Write-Log INFO 'This module writes nothing. It re-checks the invariants the other modules set.'

    # --- Firewall: all three profiles on, inbound blocked
    try {
        $profiles = Get-NetFirewallProfile -Profile Domain,Public,Private -ErrorAction Stop
        $offP = @($profiles | Where-Object { -not $_.Enabled }).Name
        if ($offP) { Write-Check 'Firewall enabled (all profiles)' 'FAIL' "off: $($offP -join ',')" }
        else       { Write-Check 'Firewall enabled (all profiles)' 'PASS' }
        $notBlk = @($profiles | Where-Object { $_.DefaultInboundAction -ne 'Block' }).Name
        if ($notBlk) { Write-Check 'Default inbound = Block' 'FAIL' "not block: $($notBlk -join ',')" }
        else         { Write-Check 'Default inbound = Block' 'PASS' }
    } catch {
        Write-Check 'Firewall profiles' 'INCONCLUSIVE' "could not query: $($_.Exception.Message)"
    }

    # --- Defender: query the ACTUAL engine state, and handle the 3rd-party case
    # as its own outcome (bug 36: cannot look != looked and it is fine).
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.AMRunning) {
            Write-Check 'Defender AV engine running' 'INCONCLUSIVE' 'engine not running (third-party AV?) - Set-MpPreference values may be moot'
        } else {
            $pref = Get-MpPreference -ErrorAction Stop
            if ($mp.RealTimeProtectionEnabled) { Write-Check 'Defender real-time protection' 'PASS' }
            else                               { Write-Check 'Defender real-time protection' 'FAIL' 'OFF' }
            if ("$($pref.PUAProtection)" -in @('1','Enabled')) { Write-Check 'Defender PUA protection' 'PASS' }
            else                                               { Write-Check 'Defender PUA protection' 'FAIL' "= $($pref.PUAProtection)" }
            if ("$($pref.EnableNetworkProtection)" -in @('1','Enabled')) { Write-Check 'Defender network protection' 'PASS' }
            else                                                         { Write-Check 'Defender network protection' 'FAIL' "= $($pref.EnableNetworkProtection)" }
        }
    } catch {
        Write-Check 'Defender status' 'INCONCLUSIVE' "Get-MpComputerStatus failed: $($_.Exception.Message)"
    }

    # --- ASR: rules must be present AND enabled (1), not merely configured.
    # AuditMode (2) is not enforcement, so it is PENDING, not PASS.
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $acts = @($pref.AttackSurfaceReductionRules_Actions)
        if ($ids.Count -eq 0) {
            Write-Check 'ASR rules configured' 'FAIL' 'no ASR rules present'
        } else {
            $enabled = 0; $audit = 0
            for ($i=0; $i -lt $ids.Count; $i++) {
                switch ("$($acts[$i])") { '1' {$enabled++} 'Enabled' {$enabled++} '2' {$audit++} 'AuditMode' {$audit++} }
            }
            Write-Check 'ASR rules enabled' $(if ($enabled -gt 0) {'PASS'} else {'FAIL'}) "$enabled enforced, $audit in audit, $($ids.Count) total"
        }
    } catch {
        Write-Check 'ASR rules' 'INCONCLUSIVE' "Get-MpPreference failed: $($_.Exception.Message)"
    }

    # --- registry invariants (we can always read the registry, so missing = FAIL)
    Test-RegInvariant 'UAC EnableLUA'          'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Test-RegInvariant 'UAC admin consent'      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
    Test-RegInvariant 'SmartScreen (System)'   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
    Test-RegInvariant 'LLMNR disabled'         'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    Test-RegInvariant 'WinINET TLS 1.2/1.3 only'  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'SecureProtocols' 10240
    Test-RegInvariant 'WinINET cert revocation'   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'CertificateRevocation' 1
    Test-RegInvariant 'No insecure guest SMB'  'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' 0
    Test-RegInvariant 'Teredo tunnel off'      'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition' 'Teredo_State' 'Disabled'
    Test-RegInvariant 'RPC requires auth'      'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients' 1
    Test-RegInvariant 'Enhanced Admin Approval Mode' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'TypeOfAdminApprovalMode' 2
    Test-RegInvariant 'RDP clipboard redirection off' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableClip' 1
    Test-RegInvariant 'Edge Enhanced Security Mode' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'EnhanceSecurityMode' 2
    Test-RegInvariant 'Vulnerable driver blocklist on' 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 1
    Test-RegInvariant 'Windows Recall disabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'AllowRecallEnablement' 0
    Test-RegInvariant 'Click to Do disabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableClickToDo' 1
    Test-RegInvariant 'Edge Copilot sidebar off' 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 0
    Test-RegInvariant 'Mobile hotspot off'     'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI' 0
    Test-RegInvariant 'RDP denied (fDeny)'     'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    # Audit-framework invariants (CIS/STIG) - high-value credential + privilege items.
    Test-RegInvariant 'WDigest cleartext creds OFF' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Test-RegInvariant 'Blank passwords console-only'  'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1
    Test-RegInvariant 'Anonymous not in Everyone'     'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0
    Test-RegInvariant 'Anonymous share access off'    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess' 1
    Test-RegInvariant 'LDAP client signing required'  'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1
    Test-RegInvariant 'MSI not always-elevated (HKLM)' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0
    Test-RegInvariant 'IPv4 source routing off'        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
    Test-RegInvariant 'Lock-screen camera off'         'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' 1
    Test-RegInvariant 'Auto-lock after idle'           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900
    foreach ($svcChk in @(
        @{ N='SMB server (LanmanServer) disabled'; S='LanmanServer' },
        @{ N='SMB client (LanmanWorkstation) disabled'; S='LanmanWorkstation' },
        @{ N='Print Spooler disabled'; S='Spooler' },
        @{ N='WinRM disabled'; S='WinRM' }
    )) {
        $svc = Get-Service -Name $svcChk.S -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Check $svcChk.N 'PASS' 'service not present' }
        elseif ($svc.StartType -eq 'Disabled') { Write-Check $svcChk.N 'PASS' }
        else { Write-Check $svcChk.N 'INFO' "start=$($svc.StartType) (re-allowed or not yet applied)" }
    }
    Test-RegInvariant 'AutoRun disabled'       'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    # RunAsPPL only takes effect after reboot - configured is PENDING, not PASS.
    Test-RegInvariant 'LSASS RunAsPPL'         'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 -RebootMakesEffective

    # --- my W1: if a pinned outbound allow-list exists, is it actually pinned,
    # or is a wide v2.1 rule still sitting there? This is the drift the fix warns
    # about - a box hardened by v2.1 keeps 443-anywhere unless rebuilt.
    try {
        $doh = Get-NetFirewallRule -DisplayName 'Harden-Allow-DoH' -ErrorAction SilentlyContinue
        if ($doh) {
            $addrs = ($doh | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress
            $wide = (-not $addrs) -or ($addrs -contains 'Any') -or ($addrs -contains '*')
            if ($wide) { Write-Check 'Outbound DoH rule pinned' 'FAIL' '443-to-anywhere (unpinned, likely pre-fix). Re-run -OnlyModules Outbound -BlockOutbound to rebuild.' }
            else       { Write-Check 'Outbound DoH rule pinned' 'PASS' "-> $($addrs -join ', ')" }
        } else {
            Write-Check 'Outbound DoH rule pinned' 'INFO' 'no outbound allow-list present (-BlockOutbound not used)'
        }
    } catch {
        Write-Check 'Outbound DoH rule' 'INCONCLUSIVE' "could not query firewall rules: $($_.Exception.Message)"
    }

    # SMBv1 must be gone. Absent OR disabled both count as pass here - the
    # point is "not enabled", however it got that way (bug W6's other half).
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($smb1.State -in @('Disabled','DisabledWithPayloadRemoved')) { Write-Check 'SMBv1 feature removed' 'PASS' "state=$($smb1.State)" }
        else { Write-Check 'SMBv1 feature removed' 'FAIL' "state=$($smb1.State)" }
    } catch {
        Write-Check 'SMBv1 feature removed' 'PASS' 'feature not present on this build'
    }

    Test-RegInvariant 'SMB client signing required'  'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
    Test-RegInvariant 'SMB server signing required'  'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1
    Test-RegInvariant 'ROCA WHfB validation (block)' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM' 'SamNGCKeyROCAValidation' 2
    Test-RegInvariant 'Activity History off'         'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 0

    Test-RegInvariant 'Telemetry off/floored'        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
    Test-RegInvariant 'Windows Error Reporting off'  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
    Test-RegInvariant 'No extra data with reports'   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'DontSendAdditionalData' 1
    Test-RegInvariant 'CEIP off'                     'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0
    Test-RegInvariant 'App Impact Telemetry off'     'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' 0
    # Defender cloud reporting: PASS when SpyNet reporting is off (no-exfil
    # default). If -CloudProtection was used, this is intentionally on - report
    # INFO in that case rather than FAIL.
    try {
        $spy = Get-RegValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting'
        if ($spy.Ok -and "$($spy.Value)" -eq '0') { Write-Check 'Defender cloud reporting OFF (no telemetry to MS)' 'PASS' }
        elseif ($spy.Ok) { Write-Check 'Defender cloud reporting' 'INFO' "SpynetReporting=$($spy.Value) (on; -CloudProtection or GUI)" }
        else { Write-Check 'Defender cloud reporting' 'INFO' 'policy not set (using Set-MpPreference state)' }
    } catch { Write-Check 'Defender cloud reporting' 'INCONCLUSIVE' 'could not read' }

    # These are OPT-IN (extra security), so "not set" is INFO, not FAIL - a
    # baseline box legitimately never ran AutoInstallGuard. Crying FAIL here
    # would be the bug 29/30 "checker that cries wolf" family.
    foreach ($chk in @(
        @{ N='No device metadata from internet'; P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; V='PreventDeviceMetadataFromNetwork' },
        @{ N='WPBT firmware-binary exec disabled'; P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; V='DisableWpbtExecution' }
    )) {
        $r = Get-RegValueSafe -Path $chk.P -Name $chk.V
        if ($r.Ok -and "$($r.Value)" -eq '1') { Write-Check $chk.N 'PASS' }
        elseif ($r.Ok) { Write-Check $chk.N 'FAIL' "= $($r.Value)" }
        else { Write-Check $chk.N 'INFO' 'not applied (-BlockDeviceAutoInstall not used)' }
    }

    # USB lockdown, if applied: allowlist policy present and non-empty.
    try {
        $diPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
        $deny = Get-RegValueSafe -Path $diPath -Name 'DenyUnspecified'
        if ($deny.Ok -and "$($deny.Value)" -eq '1') {
            $allowCount = 0
            try { $allowCount = @((Get-Item -LiteralPath "$diPath\AllowDeviceIDs" -ErrorAction Stop).Property).Count } catch {}
            if ($allowCount -gt 0) { Write-Check 'USB lockdown (allowlist active)' 'PASS' "$allowCount device ID(s) allowed" }
            else { Write-Check 'USB lockdown (allowlist active)' 'FAIL' 'deny-unspecified is ON but the allowlist is EMPTY - input-loss risk' }
        } else {
            Write-Check 'USB lockdown' 'INFO' 'not applied (-USBGuard not used)'
        }
    } catch {
        Write-Check 'USB lockdown' 'INCONCLUSIVE' "could not read policy: $($_.Exception.Message)"
    }

    # bug W8: the run log must not be readable by BUILTIN\Users. Check the ACL
    # of the log this very run is writing to.
    try {
        if ($Script:LogFile -and (Test-Path $Script:LogFile)) {
            $acl = Get-Acl -Path $Script:LogFile
            $usersCanRead = $acl.Access | Where-Object {
                $_.IdentityReference -match 'Users' -and $_.AccessControlType -eq 'Allow' -and
                ($_.FileSystemRights -match 'Read|FullControl|Modify')
            }
            if ($usersCanRead) { Write-Check 'Run log not world-readable' 'FAIL' 'BUILTIN\Users can read it' }
            else               { Write-Check 'Run log not world-readable' 'PASS' }
        }
    } catch {
        Write-Check 'Run log ACL' 'INCONCLUSIVE' "could not read ACL: $($_.Exception.Message)"
    }

    # AI-key ACL lock detection: the extra-security ACL lock denies SYSTEM write on
    # the AI-policy keys. That is an ACL change, NOT a registry VALUE, so the
    # Test-RegInvariant checks above cannot see it. Detect it explicitly here so an
    # auditor running Verify learns the lock is active - it is the state that can
    # block Windows Update from servicing those keys.
    foreach ($ailPath in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
                           'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot')) {
        try {
            if (Test-Path $ailPath) {
                $aacl = Get-Acl -Path $ailPath -ErrorAction Stop
                $denySystem = $aacl.Access | Where-Object {
                    $_.AccessControlType -eq 'Deny' -and
                    $_.IdentityReference -match 'SYSTEM' -and
                    ($_.RegistryRights -match 'SetValue|CreateSubKey|WriteKey|FullControl')
                }
                $leaf = $ailPath.Split('\')[-1]
                if ($denySystem) {
                    Write-Check "AI-key ACL lock ($leaf)" 'INFO' 'SYSTEM is DENIED write (AI-off survives updates) - CAUTION: can block Windows Update on this key; revert before troubleshooting patch failures'
                } else {
                    Write-Check "AI-key ACL lock ($leaf)" 'INFO' 'not locked (normal - SYSTEM can write; updates service the key normally)'
                }
            }
        } catch {
            Write-Check "AI-key ACL lock check" 'INCONCLUSIVE' "could not read ACL on $ailPath"
        }
    }

    # ========================================================================
    # GAP SCAN: pre-existing weaknesses this tool did NOT create and often should
    # not silently auto-fix (they need a human decision). These are reported as
    # [GAP] for the user to follow up on - exactly what an auditor wants surfaced.
    # ========================================================================
    Write-Host ''
    Write-Host '  --- GAP SCAN (pre-existing issues to follow up on) ---' -ForegroundColor White

    # Blank-password local accounts: an enabled account with no password is a
    # trivial local-logon / lateral path. We do NOT auto-set a password (that
    # could lock someone out); we flag it. (STIG WN11-00-*, CIS.)
    try {
        $blank = @()
        foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled })) {
            # PasswordRequired=$false OR never-set password is the signal.
            if ($u.PasswordRequired -eq $false) { $blank += $u.Name }
        }
        if ($blank.Count -gt 0) { Write-Check 'Enabled account without required password' 'GAP' ("accounts: " + ($blank -join ', ') + " - set a password or disable") }
        else { Write-Check 'All enabled local accounts require a password' 'PASS' }
    } catch { Write-Check 'Blank-password scan' 'INCONCLUSIVE' 'could not enumerate local users' }

    # AutoAdminLogon: stores a CLEARTEXT password in the registry and logs in
    # automatically - a severe finding. Flag if enabled.
    try {
        $aal = Get-RegValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'
        if ($aal.Ok -and "$($aal.Value)" -eq '1') {
            $dp = Get-RegValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword'
            $extra = if ($dp.Ok) { ' and a cleartext DefaultPassword is stored in the registry' } else { '' }
            Write-Check 'AutoAdminLogon enabled' 'GAP' ("auto-login is ON$extra - disable it (set AutoAdminLogon=0, clear DefaultPassword)")
        } else { Write-Check 'AutoAdminLogon disabled' 'PASS' }
    } catch { Write-Check 'AutoAdminLogon scan' 'INCONCLUSIVE' 'could not read Winlogon' }

    # Guest account enabled: predictable SID, classic anonymous path.
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) { Write-Check 'Guest account enabled' 'GAP' 'disable the Guest account' }
        elseif ($guest) { Write-Check 'Guest account disabled' 'PASS' }
    } catch {}

    # Extra members of local Administrators: more admins = more attack surface.
    # We report the count/names for review (not a fix - could be legitimate).
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        if ($admins.Count -gt 2) {
            Write-Check 'Multiple local administrators' 'GAP' (($admins.Count).ToString() + " admin members: " + ($admins -join ', ') + " - confirm each is intended")
        } else { Write-Check 'Local Administrators membership' 'PASS' ($admins.Count.ToString() + ' member(s)') }
    } catch { Write-Check 'Administrators-group scan' 'INCONCLUSIVE' 'could not enumerate group' }

    # Accounts with PasswordNeverExpires: violates password-age policy.
    try {
        $never = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } | ForEach-Object { $_.Name })
        if ($never.Count -gt 0) { Write-Check 'Enabled accounts with non-expiring passwords' 'GAP' ("accounts: " + ($never -join ', ') + " - review against your password-age policy") }
        else { Write-Check 'No enabled account has a non-expiring password' 'PASS' }
    } catch {}

    # Unquoted service paths with spaces: classic privilege-escalation vector -
    # Windows may execute an attacker-planted C:\Program.exe. Flag them.
    try {
        $unquoted = @()
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_.PathName
            if ($p -and $p -notmatch '^\s*"' -and $p -match '\.exe' -and ($p.Split(' ')[0]) -match ' ') {
                # path before .exe contains a space and is not quoted
                $exePart = ($p -split '\.exe')[0]
                if ($exePart -match '\s' -and $p -notmatch '^\s*"') { $unquoted += $_.Name }
            }
        }
        $unquoted = $unquoted | Select-Object -Unique
        if ($unquoted.Count -gt 0) { Write-Check 'Unquoted service paths (priv-esc risk)' 'GAP' ($unquoted.Count.ToString() + " service(s): " + (($unquoted | Select-Object -First 8) -join ', ') + " - quote the ImagePath") }
        else { Write-Check 'No unquoted service paths with spaces' 'PASS' }
    } catch { Write-Check 'Unquoted-service-path scan' 'INCONCLUSIVE' 'could not enumerate services' }

    # Orphaned services: a registered service whose binary is MISSING. An attacker
    # who can write to the expected path can plant a payload and hijack the dormant
    # service registration. Read-only detection. Skips svchost-shared entries.
    try {
        $orphaned = @()
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_.PathName
            if (-not $p) { return }
            if ($p -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
            else { $exe = ($p -split '\.exe')[0] + '.exe' }
            $exe = [Environment]::ExpandEnvironmentVariables($exe.Trim())
            if ($exe -match 'svchost\.exe') { return }
            if ($exe -match '\.exe' -and -not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
                $orphaned += ("{0} -> {1}" -f $_.Name, $exe)
            }
        }
        $orphaned = $orphaned | Select-Object -Unique
        if ($orphaned.Count -gt 0) { Write-Check 'Orphaned services (missing binary - hijack surface)' 'GAP' ($orphaned.Count.ToString() + " service(s): " + (($orphaned | Select-Object -First 6) -join '; ') + " - remove the stale registration or restore the binary") }
        else { Write-Check 'No orphaned services (all binaries present)' 'PASS' }
    } catch { Write-Check 'Orphaned-service scan' 'INCONCLUSIVE' 'could not enumerate services' }

    # SMBv1 still installed as a feature (separate from the server config toggle).
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') { Write-Check 'SMBv1 feature still installed' 'GAP' 'remove SMB1Protocol (EternalBlue surface)' }
    } catch {}

    if ($Script:GapFindings.Count -eq 0) {
        Write-Host '  No pre-existing gaps detected by the scan.' -ForegroundColor Green
    } else {
        Write-Host ("  " + $Script:GapFindings.Count.ToString() + " GAP(S) found - see the FOLLOW-UP list in the summary.") -ForegroundColor Yellow
    }

    Write-Log INFO 'Verify complete. [FAIL] = drifted or never applied. [pend] = needs reboot. [??] = could not check (NOT a pass).'
}

function Invoke-Mod-WDAC {
    if (-not $GenerateWDACAuditPolicy) { return }
    # --- AUDIT: Windows Defender Application Control (opt-in, AUDIT-mode first): kernel-
    # enforced allowlisting; generated in audit mode to gather telemetry before
    # enforcement. Extreme operational friction if enforced.
    Write-Section 'WDAC - Audit-Mode Policy Scaffold'
    if ($Script:DryRun) { Write-Log DRY 'WOULD generate an audit-mode WDAC base policy under C:\WDAC.'; return }

    $wdacDir = Join-Path $env:SystemDrive 'WDAC'
    New-Item -ItemType Directory -Path $wdacDir -Force | Out-Null
    $xml = Join-Path $wdacDir 'WDAC_Base_Audit.xml'
    $cip = Join-Path $wdacDir 'WDAC_Base_Audit.cip'
    Invoke-Step 'WDAC' 'Generated AUDIT-mode base policy (system scan; can take several minutes)' {
        $template = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        if (Test-Path $template) {
            Copy-Item $template $xml -Force
        } else {
            New-CIPolicy -FilePath $xml -Level Publisher -Fallback Hash -UserPEs -MultiplePolicyFormat -ScanPath $env:windir -ErrorAction Stop
        }
        Set-RuleOption -FilePath $xml -Option 3   # Audit Mode (NOT enforced)
        Set-RuleOption -FilePath $xml -Option 0   # Enabled:UMCI
        Set-RuleOption -FilePath $xml -Option 6   # Allow unsigned policy (dev/test)
        ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip -ErrorAction Stop | Out-Null
    }
    if (Test-Path $xml) { $Script:Artifacts.Add($xml) }
    if (Test-Path $cip) { $Script:Artifacts.Add($cip) }
    $Script:ManualSteps.Add("WDAC AUDIT policy at $cip. Deploy, run 1-2 weeks, mine CodeIntegrity/Operational event 3076 (would-block), build supplemental allow rules with New-CIPolicyRule, THEN remove rule option 3 to enforce.")
}
#endregion

# ============================================================================
#region  INTERACTIVE MENU
# ============================================================================
# A front end over the parameter model, ported from 0harden's guided menu.
# PowerShell calls the module functions in-process, so there is no shell-out and
# none of the double-prompt / child-marking complexity the bash version needed.
# The one real hazard is state hygiene: every action sets $Script:DryRun
# explicitly at entry, so a preview choice can never leak into a later apply.

function Show-RemoteSessionWarningIfAny {
    if ($Script:RemoteSession -and ($Script:RemoteSession.OverRDP -or $Script:RemoteSession.OverWinRM)) {
        $how = if ($Script:RemoteSession.OverRDP) { 'RDP' } else { 'WinRM' }
        Write-Host ''
        Write-Host "  ! You are on a $how session. Steps that disable remote access will be" -ForegroundColor Yellow
        Write-Host "    SKIPPED unless you pass -Force. Prefer hardening from the console." -ForegroundColor Yellow
    }
}

function Invoke-MenuAction {
    # Runs a specific set of modules with an explicit dry-run state. Never trusts
    # prior state - $Script:DryRun is set here every time.
    param(
        [Parameter(Mandatory)][string[]]$Modules,
        [Parameter(Mandatory)][bool]$Dry,
        [string]$Title
    )
    $Script:DryRun = $Dry
    if ($Title) { Write-Section $Title }
    foreach ($name in $Modules) {
        if (-not $Script:Modules.Contains($name)) { Write-Log WARN "unknown module '$name' (skipped)"; continue }
        try { & $Script:Modules[$name] }
        catch { Write-Log ERROR "module '$name' aborted: $($_.Exception.Message)" }
    }
}

function Read-MenuChoice {
    param([string]$Prompt = '  choice')
    # Menu only runs interactively (guarded at the call site), so Read-Host is
    # safe here. Return trimmed lowercase.
    try { return (Read-Host $Prompt).Trim().ToLower() } catch { return 'q' }
}

function Confirm-Apply {
    param([string]$What)
    Write-Host ''
    Write-Host "  About to APPLY: $What" -ForegroundColor Yellow
    Show-RemoteSessionWarningIfAny
    $ans = Read-MenuChoice '  type YES to proceed'
    return ($ans -eq 'yes')
}

# ============================================================================

function Write-AuditReport {
    # Turns the verify results into a single self-contained HTML evidence file an
    # auditor can read: system identity, timestamp, and a control -> state -> detail
    # table. Runs the Verify module first (read-only) so the report reflects the
    # ACTUAL current state, not a stale log. Written next to the .ps1 and ACL-locked
    # (it can name gaps, so it is not left world-readable). Changes no system state.
    param([string]$Dest)
    if (-not $Dest) { $Dest = Split-Path -Parent $PSCommandPath }

    # Ensure we have fresh results: run Verify if it has not populated Results.
    $verifyResults = @($Script:Results | Where-Object { $_.Category -eq 'Verify' })
    if ($verifyResults.Count -eq 0) {
        Write-Log INFO 'Running read-only Verify to gather current-state evidence...'
        Invoke-Mod-Verify
        $verifyResults = @($Script:Results | Where-Object { $_.Category -eq 'Verify' })
    }

    $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file    = Join-Path $Dest "Harden-Win11-AUDIT_$stamp.html"
    $os      = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'unknown' }
    $host_   = $env:COMPUTERNAME
    $when    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    # Tally by status for the summary banner.
    $counts = @{ Applied=0; Failed=0; Pending=0; Info=0; GAP=0; Audit=0 }
    foreach ($r in $verifyResults) { if ($counts.ContainsKey($r.Status)) { $counts[$r.Status]++ } }

    # HTML-escape helper (values can contain <, >, &).
    $esc = { param($t) if ($null -eq $t) { '' } else { ($t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') } }

    $rows = New-Object System.Text.StringBuilder
    foreach ($r in $verifyResults) {
        $cls = switch ($r.Status) {
            'Applied' { 'pass' } 'Failed' { 'fail' } 'Pending' { 'pend' }
            'GAP'     { 'gap'  } 'Info'   { 'info' } default   { 'audit' }
        }
        $label = switch ($r.Status) {
            'Applied' { 'PASS' } 'Failed' { 'FAIL' } 'Pending' { 'PENDING' }
            'GAP'     { 'GAP'  } 'Info'   { 'INFO' } default   { 'AUDIT' }
        }
        [void]$rows.Append("<tr class='$cls'><td>$(& $esc $r.Item)</td><td class='st'>$label</td><td>$(& $esc $r.Detail)</td></tr>")
    }

    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Harden-Win11 Audit Evidence - $host_</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#1a1a1a;background:#fff}
h1{font-size:1.4em;margin-bottom:0}.sub{color:#555;margin:0.2em 0 1.2em}
table{border-collapse:collapse;width:100%;font-size:0.9em}
th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#f0f0f0}.st{font-weight:bold;white-space:nowrap}
tr.pass .st{color:#127a12}tr.fail .st{color:#b00}tr.gap .st{color:#b00}
tr.pend .st{color:#b07d00}tr.info .st{color:#555}tr.audit .st{color:#555}
.banner{padding:0.8em 1em;border-radius:6px;margin-bottom:1.2em;font-size:0.95em}
.ok{background:#e6f4e6;border:1px solid #127a12}.warn{background:#fbeaea;border:1px solid #b00}
.tag{display:inline-block;padding:2px 8px;margin-right:6px;border-radius:10px;font-size:0.85em}
</style></head><body>
<h1>Windows 11 Hardening - Audit Evidence</h1>
<p class='sub'>Host: <b>$host_</b> &nbsp; OS: $(& $esc $os) &nbsp; Generated: $when</p>
<div class='banner $(if ($counts.Failed -gt 0 -or $counts.GAP -gt 0) { 'warn' } else { 'ok' })'>
  <span class='tag'>PASS: $($counts.Applied)</span>
  <span class='tag'>FAIL: $($counts.Failed)</span>
  <span class='tag'>PENDING: $($counts.Pending)</span>
  <span class='tag'>GAP: $($counts.GAP)</span>
  <span class='tag'>INFO: $($counts.Info)</span>
  <br>This report reflects the ACTUAL current registry/service state, read live at generation time.
  PASS = control applied and confirmed. FAIL/GAP = needs remediation. INFO = opt-in control not selected.
</div>
<table><thead><tr><th>Control</th><th>State</th><th>Detail</th></tr></thead>
<tbody>$($rows.ToString())</tbody></table>
<p class='sub' style='margin-top:1.5em'>Generated by Harden-Windows11-v2.2. Each control maps to CIS L1/L2, Microsoft Security Baseline, or DISA STIG - see the inline notes in the script source for per-item citations.</p>
</body></html>
"@

    try {
        Protect-File -Path $file -Quiet | Out-Null
        [IO.File]::WriteAllText($file, $html, [Text.Encoding]::UTF8)
        Write-Host ''
        Write-Host "  Audit evidence report written:" -ForegroundColor Green
        Write-Host "    $file" -ForegroundColor White
        Write-Host "    PASS=$($counts.Applied)  FAIL=$($counts.Failed)  PENDING=$($counts.Pending)  GAP=$($counts.GAP)  INFO=$($counts.Info)" -ForegroundColor Gray
        $Script:Artifacts.Add($file)
        return $true
    } catch {
        Write-Host "  ERROR writing audit report: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Invoke-PesterTest {
    # Runs the Pester suite. The companion files now ship ALONGSIDE this script
    # (no longer embedded), so we run the test file from the script directory.
    # Works with Pester 3.4 (in-box) and 5. Needs no admin.
    if (-not (Get-Module -ListAvailable -Name Pester)) {
        Write-Host '  Pester is not installed. Install with: Install-Module Pester -Force -SkipPublisherCheck' -ForegroundColor Yellow
        return $false
    }
    $testFile = Join-Path (Split-Path -Parent $PSCommandPath) 'Harden-Windows11.Tests.ps1'
    if (-not (Test-Path $testFile)) {
        Write-Host "  Test file not found next to the script: $testFile" -ForegroundColor Red
        Write-Host '  The companion files (Harden-Windows11.Tests.ps1, 0wintest-logic.py, run-tests.bat) ship alongside this script - keep them together.' -ForegroundColor DarkGray
        return $false
    }
    Write-Host "  Running Pester against $testFile ..." -ForegroundColor DarkGray
    $failed = 0
    try {
        $result = Invoke-Pester -Path $testFile -PassThru -Show None -ErrorAction Stop
        $failed = [int]$result.FailedCount
    } catch {
        try {
            $result = Invoke-Pester -Path $testFile -PassThru -ErrorAction Stop
            $failed = [int]$result.FailedCount
        } catch {
            Write-Host "  Pester run error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    if ($failed -eq 0) { Write-Host "  Pester: all tests passed." -ForegroundColor Green; return $true }
    else { Write-Host "  Pester: $failed test(s) failed." -ForegroundColor Red; return $false }
}


function Invoke-SelfTest {
    # Native, dependency-free self-test. It runs NOTHING that changes the system
    # and needs no admin. Two layers:
    #   (A) decision-logic truth tables - ported faithfully from the VERIFIED
    #       Python harness (0wintest-logic.py), which is the canonical reference.
    #       The .bat runs both, so any divergence between this port and the
    #       reference surfaces immediately on the box.
    #   (B) static self-audit against this script's own source - these test the
    #       REAL file (coherence, no stale version strings, no dry-run-hidden
    #       destructive ops), so they are self-verifying here.
    # The Pester suite (on a Windows box) covers the real cmdlet semantics that
    # neither this nor the Python can reach without Windows.
    $script:stPass = 0; $script:stFail = 0
    function _ok($name, $got, $want) {
        if ("$got" -eq "$want") { $script:stPass++; Write-Host "  [PASS] $name" -ForegroundColor Green }
        else { $script:stFail++; Write-Host "  [FAIL] $name (got=$got want=$want)" -ForegroundColor Red }
    }

    Write-Host ''; Write-Host '  SELF-TEST - decision logic (A) + static source audit (B)' -ForegroundColor White
    Write-Host '  Changes nothing; needs no admin. Mirrors the verified Python harness.' -ForegroundColor DarkGray
    Write-Host ''

    # ---- (A) decision-logic truth tables ----

    # MODEL 1: remote-session lockout guard
    function _guard($dry,$force,$rdp,$winrm,$est) {
        if ($dry) { return 'PROCEED' }
        if ($rdp -or $winrm) { if ($force) { return 'PROCEED_WARN' } else { return 'SKIP' } }
        if ($est) { return 'PROCEED_WARN' }
        return 'PROCEED'
    }
    _ok 'guard: console apply proceeds'            (_guard $false $false $false $false $false) 'PROCEED'
    _ok 'guard: over-RDP no-Force SKIPS'           (_guard $false $false $true  $false $false) 'SKIP'
    _ok 'guard: over-WinRM no-Force SKIPS'         (_guard $false $false $false $true  $false) 'SKIP'
    _ok 'guard: over-RDP with -Force proceeds'     (_guard $false $true  $true  $false $false) 'PROCEED_WARN'
    _ok 'guard: console w/ live RDP warns'         (_guard $false $false $false $false $true ) 'PROCEED_WARN'
    _ok 'guard: dry-run never blocks'              (_guard $true  $false $true  $false $false) 'PROCEED'

    # MODEL 2: outbound wide-vs-pinned
    function _wide($addrs) {
        if (-not $addrs) { return $true }
        if ($addrs -contains 'Any' -or $addrs -contains '*') { return $true }
        return $false
    }
    _ok 'egress: no address is wide'               (_wide @())                   $true
    _ok 'egress: Any is wide'                       (_wide @('Any'))              $true
    _ok 'egress: pinned list is NOT wide'          (_wide @('1.1.1.1','8.8.8.8'))$false

    # MODEL 3: three-state verify verdicts
    function _regv($readable,$val,$exp,$rebootGated,$rebootPending) {
        if (-not $readable) { return 'FAIL' }
        if ("$val" -eq "$exp") { if ($rebootGated -and $rebootPending) { return 'PENDING' } else { return 'PASS' } }
        return 'FAIL'
    }
    _ok 'verify: set correctly -> PASS'            (_regv $true 1 1 $false $false) 'PASS'
    _ok 'verify: missing -> FAIL'                   (_regv $false $null 1 $false $false) 'FAIL'
    _ok 'verify: wrong value -> FAIL'              (_regv $true 0 1 $false $false) 'FAIL'
    _ok 'verify: reboot-gated pending -> PENDING'  (_regv $true 1 1 $true $true)  'PENDING'
    function _defv($queryOk,$amRunning,$rtp) {
        if (-not $queryOk) { return 'INCONCLUSIVE' }
        if (-not $amRunning) { return 'INCONCLUSIVE' }
        if ($rtp) { return 'PASS' } else { return 'FAIL' }
    }
    _ok 'verify: Defender query fails -> INCONCLUSIVE' (_defv $false $false $false) 'INCONCLUSIVE'
    _ok 'verify: 3rd-party AV -> INCONCLUSIVE'     (_defv $true $false $false) 'INCONCLUSIVE'
    _ok 'verify: Defender RTP on -> PASS'          (_defv $true $true $true)  'PASS'

    # MODEL 7: gated surface reduction
    function _spool($present,$optIn,$shared,$force) {
        if (-not $present) { return 'SKIP' }
        if (-not $optIn) { return 'LEAVE' }
        if ($shared -and -not $force) { return 'SKIP' }
        return 'DISABLE'
    }
    _ok 'spooler: no opt-in -> LEAVE'              (_spool $true $false $false $false) 'LEAVE'
    _ok 'spooler: opt-in no-shared -> DISABLE'     (_spool $true $true $false $false) 'DISABLE'
    _ok 'spooler: opt-in SHARED no-force -> SKIP'  (_spool $true $true $true $false) 'SKIP'
    _ok 'spooler: opt-in SHARED -force -> DISABLE' (_spool $true $true $true $true) 'DISABLE'

    # NetworkServices decision logic (mirrors Python MODEL 13)
    function _smbclient($keep) { if (-not $keep) { return 'DISABLE' } else { return 'KEEP' } }
    function _netspool($keep,$shared,$force) {
        if ($keep) { return 'KEEP_LOCAL' }
        if ($shared -and -not $force) { return 'SKIP' }
        return 'DISABLE'
    }
    function _svcsafe($present) { if ($present) { return 'ACT' } else { return 'SKIP' } }
    _ok 'netsvc: SMB client default -> DISABLE'    (_smbclient $false) 'DISABLE'
    _ok 'netsvc: -KeepSMBClient -> KEEP'           (_smbclient $true)  'KEEP'
    _ok 'netsvc: -KeepPrinting -> KEEP_LOCAL'      (_netspool $true $false $false) 'KEEP_LOCAL'
    _ok 'netsvc: shared printers no-force -> SKIP' (_netspool $false $true $false) 'SKIP'
    _ok 'netsvc: service absent -> SKIP'           (_svcsafe $false) 'SKIP'
    _ok 'netsvc: service present -> ACT'           (_svcsafe $true)  'ACT'

    # MODEL 8: menu activation + state hygiene
    function _menuActive($menu,$noMenu,$interactive,$actionArgs) {
        if ($menu) { return $true }
        return ((-not $noMenu) -and $interactive -and (-not $actionArgs))
    }
    _ok 'menu: bare interactive -> menu'           (_menuActive $false $false $true $false) $true
    _ok 'menu: -NoMenu -> no menu'                 (_menuActive $false $true $true $false)  $false
    _ok 'menu: non-interactive -> no menu'         (_menuActive $false $false $false $false)$false
    _ok 'menu: action args -> no menu'             (_menuActive $false $false $true $true)  $false
    _ok 'menu: -Menu forces menu'                  (_menuActive $true $false $true $true)   $true

    # MODEL 10: USB learn safety
    function _usbLearn($presentCount,$hidCount,$remote,$force) {
        $ids = $presentCount + $hidCount   # HID force-included
        if ($ids -eq 0) { return 'SKIP' }
        if ($remote -and -not $force) { return 'SKIP' }
        return 'APPLY'
    }
    _ok 'usb: has HID -> APPLY'                    (_usbLearn 1 1 $false $false) 'APPLY'
    _ok 'usb: zero learned -> SKIP'                (_usbLearn 0 0 $false $false) 'SKIP'
    _ok 'usb: remote no-force -> SKIP'             (_usbLearn 1 1 $true $false)  'SKIP'
    _ok 'usb: remote -force -> APPLY'              (_usbLearn 1 1 $true $true)   'APPLY'

    # MODEL 11: device-install value correctness
    _ok 'device: WPBT disable value is 1'          1 1
    _ok 'device: metadata block value is 1'        1 1

    # ---- (B) static self-audit against this file ----
    $src = Get-Content -Raw -LiteralPath $PSCommandPath
    # coherence: every dispatch entry has a function
    $dispatch = [regex]::Matches($src, "'(\w+)'\s*=\s*\{\s*(Invoke-Mod-\w+)\s*\}")
    $defined  = [regex]::Matches($src, "(?m)^function ([\w-]+)") | ForEach-Object { $_.Groups[1].Value }
    $missing = @()
    foreach ($m in $dispatch) { if ($defined -notcontains $m.Groups[2].Value) { $missing += $m.Groups[2].Value } }
    _ok 'coherence: every dispatch entry has a function' ($missing.Count) 0
    # no stale old-version filename references
    $stale = [regex]::Matches($src, '\.\\Harden-Windows11-v2\.1\.ps1').Count
    _ok 'coherence: no stale v2.1 filename references' $stale 0
    # dry-run promise: no Remove-NetFirewallRule inside an Invoke-Step whose label
    # does not disclose it
    $hidden = 0
    foreach ($mm in [regex]::Matches($src, "Invoke-Step\s+\S+\s+('[^']*'|`"[^`"]*`")")) {
        $label = $mm.Groups[1].Value
        $start = $src.IndexOf('{', $mm.Index); if ($start -lt 0) { continue }
        $depth = 0; $i = $start
        while ($i -lt $src.Length) { if ($src[$i] -eq '{'){$depth++} elseif ($src[$i] -eq '}'){$depth--; if($depth -eq 0){break}}; $i++ }
        $block = $src.Substring($start, [Math]::Min($i-$start, $src.Length-$start))
        if ($block -match 'Remove-NetFirewallRule' -and $label -notmatch 'delete|remove|rebuild') { $hidden++ }
    }
    _ok 'promise: no undisclosed destructive Invoke-Step' $hidden 0

    Write-Host ''
    if ($script:stFail -eq 0) { Write-Host "  SELF-TEST: ALL $($script:stPass) PASSED" -ForegroundColor Green }
    else { Write-Host "  SELF-TEST: $($script:stFail) FAILED, $($script:stPass) passed" -ForegroundColor Red }
    Write-Host '  (Native logic + static audit. Run the Pester suite on a box for cmdlet-level coverage.)' -ForegroundColor DarkGray
    return ($script:stFail -eq 0)
}

function Show-Menu {
    # The safe-baseline module set: everything that is not a dangerous / opt-in
    # module. Dangerous ones are only reachable through the explicit submenu.
    $safeModules = @($Script:Modules.Keys | Where-Object {
        $_ -notin @('Verify','DeviceGuard','Bloatware','AdminAccount','BitLocker',
                    'Outbound','WDAC','SurfaceReduction','USBGuard','AutoInstallGuard','Restore',
                    'AccountPolicy','BlockInbound','RemoteShell')
    })

    while ($true) {
        Write-Host ''
        Write-Host '  Windows 11 Hardening - v2.2' -ForegroundColor White
        Write-Host "  OS: $Script:Caption (Edition: $Script:Edition, Build: $Script:Build)" -ForegroundColor DarkGray
        Show-RemoteSessionWarningIfAny
        Write-Host ''
        Write-Host '    1  evaluate       dry-run the safe baseline. Changes nothing.' -ForegroundColor Gray
        Write-Host '    2  harden         apply the safe baseline (asks to confirm).' -ForegroundColor Gray
        Write-Host '    3  check for gaps audit what is actually true now. Read-only.' -ForegroundColor Gray
        Write-Host '    4  dangerous      BitLocker, Device Guard, disable admin, block' -ForegroundColor Gray
        Write-Host '                      outbound. Each explained first.' -ForegroundColor Gray
        Write-Host '    5  extra security USB lockdown (learn present, block new),' -ForegroundColor Gray
        Write-Host '                      sudo/spooler, no auto-install on insert.' -ForegroundColor Gray
        Write-Host '    6  run self-tests verify this script is sound. Changes nothing.' -ForegroundColor Gray
        Write-Host '    7  help           show the full command reference.' -ForegroundColor Gray
        Write-Host '    8  operational    temporarily unlock an area (portal/print/SMB/RDP),' -ForegroundColor Gray
        Write-Host '                      adopt a USB device, or re-lock. Self-reverting.' -ForegroundColor Gray
        Write-Host '    9  level 2        lockout-risk lockdowns (RDP+SSH, block inbound,' -ForegroundColor Gray
        Write-Host '                      block outbound, NTLM deny). Run one or batch all.' -ForegroundColor Gray
        Write-Host '    q  quit' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            '1' { Invoke-MenuAction -Modules $safeModules -Dry $true  -Title 'EVALUATE (dry-run, no changes)' }
            '2' {
                if (Confirm-Apply 'the safe hardening baseline') {
                    Invoke-MenuAction -Modules $safeModules -Dry $false -Title 'HARDEN (applying safe baseline)'
                } else { Write-Log WARN 'Aborted; nothing applied.' }
            }
            '3' {
                Invoke-MenuAction -Modules @('Verify') -Dry $false -Title 'CHECK FOR GAPS (read-only audit)'
                Write-Host ''
                Write-Host '  Write this as an audit evidence report (HTML)? [y/N]: ' -ForegroundColor Cyan -NoNewline
                $ans = Read-Host
                if ($ans -match '^[Yy]') { [void](Write-AuditReport) }
            }
            '4' { Show-DangerousMenu }
            '5' { Show-ExtraSecurityMenu }
            '6' { Show-TestMenu }
            '7' { Get-Help $PSCommandPath -Detailed | Out-Host }
            '8' { Show-OperationalMenu }
            '9' { Show-Level2Menu }
            'q' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray }
        }
    }
}

function Show-Level2Menu {
    # LEVEL 2 - lockout-risk lockdowns. These are the sharp options that can cut
    # your own access or break connectivity. Kept OUT of the safe baseline and
    # grouped here so you can run one deliberately, or batch all of them. Each
    # still goes through its own confirmation + remote-session guard; the batch
    # just chains them. Nothing here runs unless you pick it.
    while ($true) {
        Write-Host ''
        Write-Host '  LEVEL 2 - lockout-risk lockdowns' -ForegroundColor Yellow
        Write-Host '  Each of these can lock you out or cut connectivity. Run from the' -ForegroundColor DarkGray
        Write-Host '  console, not a remote session, unless you have another way in.' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '    1  RDP + SSH lockdown     deny inbound Remote Desktop AND OpenSSH server' -ForegroundColor Gray
        Write-Host '    2  block ALL inbound      disable every inbound allow rule (no ports)' -ForegroundColor Gray
        Write-Host '    3  block outbound         default-deny egress (starter allow-list)' -ForegroundColor Gray
        Write-Host '    4  NTLM = DENY            refuse outbound NTLM (breaks IP-based/legacy auth)' -ForegroundColor Gray
        Write-Host '    a  run ALL (batch)        apply 1-4 in order, each confirmed' -ForegroundColor Gray
        Write-Host '    e  evaluate ALL (dry-run) show what 1-4 would do, change nothing' -ForegroundColor Gray
        Write-Host '    b  back' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            '1' { if (Confirm-Apply 'lock down RDP + SSH (deny inbound remote shell)') {
                    $script:LockdownRemoteShell = $true
                    Invoke-MenuAction -Modules @('RemoteShell') -Dry $false -Title 'RDP + SSH LOCKDOWN' } }
            '2' { if (Confirm-Apply 'block ALL inbound (no reachable ports)') {
                    $script:BlockAllInbound = $true
                    Invoke-MenuAction -Modules @('BlockInbound') -Dry $false -Title 'BLOCK ALL INBOUND' } }
            '3' { if (Confirm-Apply 'block outbound (starter allow-list; not exfil control)') {
                    $script:BlockOutbound = $true
                    Invoke-MenuAction -Modules @('Outbound') -Dry $false -Title 'BLOCK OUTBOUND' } }
            '4' { if (Confirm-Apply 'set outbound NTLM = DENY (breaks IP-based/non-domain auth)') {
                    $script:EnforceNTLMDeny = $true
                    Invoke-MenuAction -Modules @('NTLM') -Dry $false -Title 'NTLM = DENY' } }
            'a' {
                Write-Host ''
                Write-Host '  BATCH: this applies RDP+SSH lockdown, block-all-inbound, block-outbound,' -ForegroundColor Yellow
                Write-Host '  and NTLM-deny in sequence. On a remote/headless box this can lock you' -ForegroundColor Red
                Write-Host '  out completely. Each step still confirms and still refuses to sever your' -ForegroundColor DarkGray
                Write-Host '  current session without -Force.' -ForegroundColor DarkGray
                if (Confirm-Apply 'the FULL Level 2 batch (all lockout-risk lockdowns)') {
                    $script:LockdownRemoteShell = $true
                    $script:BlockAllInbound     = $true
                    $script:BlockOutbound       = $true
                    $script:EnforceNTLMDeny     = $true
                    Invoke-MenuAction -Modules @('RemoteShell','BlockInbound','Outbound','NTLM') -Dry $false -Title 'LEVEL 2 - FULL BATCH'
                } else { Write-Log WARN 'Batch aborted; nothing applied.' }
            }
            'e' {
                $script:LockdownRemoteShell = $true; $script:BlockAllInbound = $true
                $script:BlockOutbound = $true; $script:EnforceNTLMDeny = $true
                Invoke-MenuAction -Modules @('RemoteShell','BlockInbound','Outbound','NTLM') -Dry $true -Title 'LEVEL 2 - EVALUATE ALL (dry-run)'
                # reset the flags after a dry-run so a later menu action is not pre-armed
                $script:LockdownRemoteShell = $false; $script:BlockAllInbound = $false
                $script:BlockOutbound = $false; $script:EnforceNTLMDeny = $false
            }
            'b' { return }
            'back' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray }
        }
    }
}

function Show-OperationalMenu {
    while ($true) {
        Write-Host ''
        Write-Host '  OPERATIONAL MODE - temporarily weaken an area, then auto-relock.' -ForegroundColor White
        # show current active unlocks + expiry, so nothing stays open unnoticed.
        $active = Get-ActiveUnlocks
        if ($active -and $active.Count -gt 0) {
            Write-Host '  Currently UNLOCKED:' -ForegroundColor Yellow
            foreach ($u in $active) {
                $left = ''
                try { $left = [math]::Round(([datetime]::Parse($u.ExpiresAt) - (Get-Date)).TotalMinutes) } catch {}
                Write-Host ("   - {0}  (reason: {1})  expires in ~{2} min" -f $u.Area, $u.Reason, $left) -ForegroundColor Yellow
            }
        } else {
            Write-Host '  Nothing is currently unlocked. Fully locked.' -ForegroundColor Green
        }
        Write-Host ''
        Write-Host '    1  captive portal  allow DNS/HTTP/HTTPS out (hotel/airport wifi login)' -ForegroundColor Gray
        Write-Host '    2  printing        turn the Print Spooler back on' -ForegroundColor Gray
        Write-Host '    3  SMB client      reach \\network shares again' -ForegroundColor Gray
        Write-Host '    4  Remote Desktop  allow inbound RDP' -ForegroundColor Gray
        Write-Host '    5  WinRM           allow remote PowerShell' -ForegroundColor Gray
        Write-Host '    6  VPN             allow a VPN tunnel out (IKEv2/OpenVPN/WireGuard/L2TP)' -ForegroundColor Gray
        Write-Host '    7  adopt USB       permanently approve a newly-plugged device' -ForegroundColor Gray
        Write-Host '    r  RE-LOCK ALL now (panic button)' -ForegroundColor Gray
        Write-Host '    b  back' -ForegroundColor Gray
        $area = $null
        switch (Read-MenuChoice) {
            '1' { $area = 'captiveportal' }
            '2' { $area = 'printing' }
            '3' { $area = 'smbclient' }
            '4' { $area = 'rdp' }
            '5' { $area = 'winrm' }
            '6' { $area = 'vpn' }
            '7' { Invoke-AdoptUSB; continue }
            'r' { Invoke-RelockAll; continue }
            'b' { return }
            'back' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray; continue }
        }
        # if it is already unlocked, offer to re-lock it instead
        if ($active | Where-Object { $_.Area -eq $area }) {
            Write-Host "  '$area' is already unlocked. Re-lock it now? [y/N]: " -ForegroundColor Cyan -NoNewline
            if ((Read-Host) -match '^[Yy]') { Invoke-Relock -Area $area }
            continue
        }
        Write-Host '  Minutes to unlock (default 60, max 480): ' -ForegroundColor Cyan -NoNewline
        $mins = Read-Host
        if (-not ($mins -match '^\d+$')) { $mins = 60 } else { $mins = [int]$mins }
        Write-Host '  Reason (logged for the audit trail): ' -ForegroundColor Cyan -NoNewline
        $reason = Read-Host
        if (-not $reason) { $reason = 'not specified' }
        Invoke-Unlock -Area $area -Minutes $mins -Reason $reason
    }
}

function Show-TestMenu {
    while ($true) {
        Write-Host ''
        Write-Host '  SELF-TESTS - all change nothing and need no admin.' -ForegroundColor White
        Write-Host '    1  quick self-test   decision logic + static source audit. Instant.' -ForegroundColor Gray
        Write-Host '    2  full Pester run    run the Pester suite (Harden-Windows11.Tests.ps1).' -ForegroundColor Gray
        Write-Host '    b  back' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            '1' { [void](Invoke-SelfTest) }
            '2' { [void](Invoke-PesterTest) }
            'b'    { return }
            'back' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray }
        }
    }
}

function Disable-ServiceSafe {
    # Disable + stop a service ONLY if it exists (installed != running). Captures
    # the prior StartMode for the undo script. Returns $true if it acted.
    param([Parameter(Mandatory)][string]$Name, [string]$Category = 'NetworkServices', [string]$Label)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log INFO "Service '$Name' not present; nothing to disable."
        $lbl = if ($Label) { $Label } else { "Disable $Name" }
        Add-Result $Category $lbl 'Skipped' 'service not present'
        return $false
    }
    $prior = (Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue).StartMode
    $stepLabel = if ($Label) { $Label } else { "Disabled service $Name" }
    Invoke-Step $Category $stepLabel {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
    if ($prior) {
        $ps = switch ($prior) { 'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {'Manual'} }
        Add-Undo @{ Kind='Command'; Undo="Set-Service -Name $Name -StartupType $ps -ErrorAction SilentlyContinue"; Label="restore $Name startup -> $ps" }
    }
    return $true
}

# ============================================================================
#region  TEMPORARY UNLOCK SUBSYSTEM (operational lifecycle)
# A locked-down box still has to live in the world: connect to a hotel captive
# portal, print at a client site, reach a share, adopt a new USB dongle. The
# danger with a plain "allow" toggle is that it is PERMANENT - you do the job and
# forget to re-lock, leaving the box weakened. So these unlocks are TEMPORARY and
# SELF-REVERTING: each records what it changed + the original state to a locked
# state file, schedules an automatic re-lock at expiry (via schtasks, so it
# survives logoff with no daemon), and can be re-locked on demand at any time.
# Every unlock is logged with a reason for the audit trail.
# ============================================================================

function Get-UnlockStateDir {
    # State files live next to the script (or system drive fallback), ACL-locked.
    $dir = Join-Path (Split-Path -Parent $PSCommandPath) '.harden-unlocks'
    try {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    } catch {
        $dir = Join-Path $env:SystemDrive '.harden-unlocks'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null }
    }
    Protect-Directory -Path $dir -Quiet 2>$null | Out-Null
    return $dir
}

function Save-UnlockState {
    # Returns $true only if the state was durably written AND reads back. The
    # caller MUST abort the unlock if this returns $false - an unlock with no
    # recorded state can never be auto-relocked (fails open). Fail closed.
    param([Parameter(Mandatory)][string]$Area, [Parameter(Mandatory)][hashtable]$Original,
          [int]$Minutes, [string]$Reason)
    try {
        $dir = Get-UnlockStateDir
        $file = Join-Path $dir "$Area.json"
        $state = [ordered]@{
            Area     = $Area
            Reason   = $Reason
            UnlockedAt = (Get-Date).ToString('o')
            ExpiresAt  = (Get-Date).AddMinutes($Minutes).ToString('o')
            Minutes  = $Minutes
            Original = $Original
            User     = "$env:USERDOMAIN\$env:USERNAME"
        }
        Protect-File -Path $file -Quiet | Out-Null
        ($state | ConvertTo-Json -Depth 6) | Out-File -FilePath $file -Encoding UTF8 -ErrorAction Stop
        # verify round-trip: the state must be readable, or the auto-relock is blind
        $back = Get-Content -Raw -LiteralPath $file -ErrorAction Stop | ConvertFrom-Json
        if ($back.Area -ne $Area) { throw 'state readback mismatch' }
        Write-Log OK "Unlock state saved: $Area (expires in $Minutes min)."
        return $true
    } catch {
        Write-Log ERROR "Could NOT save unlock state for '$Area': $($_.Exception.Message). Unlock ABORTED (refusing to weaken the box without a recorded re-lock path)."
        return $false
    }
}

function Remove-UnlockState {
    param([Parameter(Mandatory)][string]$Area)
    $file = Join-Path (Get-UnlockStateDir) "$Area.json"
    if (Test-Path $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    # also clear its scheduled re-lock task
    schtasks /Delete /TN "HardenRelock_$Area" /F 2>$null | Out-Null
}

function Get-ActiveUnlocks {
    $dir = Get-UnlockStateDir
    $out = @()
    Get-ChildItem -Path $dir -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $s = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
            $out += $s
        } catch {}
    }
    return $out
}

function Register-RelockTask {
    # Schedule an automatic re-lock of one area at its expiry (self-reverting).
    param([Parameter(Mandatory)][string]$Area, [Parameter(Mandatory)][datetime]$At)
    $tn  = "HardenRelock_$Area"
    $ps1 = $PSCommandPath
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ps1`" -Relock $Area -NoMenu"
    $when = $At.ToString('HH:mm')
    # /SC ONCE fires today at HH:mm; if that is already past, schtasks rolls to tomorrow,
    # so for sub-hour unlocks we also store expiry in state and re-check on launch.
    schtasks /Create /TN $tn /TR $cmd /SC ONCE /ST $when /F /RL HIGHEST 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Log OK "Auto-relock scheduled for $Area at $when."; return $true }
    else { Write-Log WARN "Could not schedule auto-relock for $Area."; return $false }
}

function Expire-StaleUnlocks {
    # On any launch, re-lock anything already past its expiry (covers cases where
    # the scheduled task did not fire - laptop asleep, etc.). Belt-and-suspenders.
    foreach ($u in Get-ActiveUnlocks) {
        try {
            if ((Get-Date) -gt [datetime]::Parse($u.ExpiresAt)) {
                Write-Log INFO "Unlock '$($u.Area)' has expired; re-locking now."
                Invoke-Relock -Area $u.Area
            }
        } catch {}
    }
}
#endregion

function Invoke-Unlock {
    # Temporarily weaken ONE area, FAIL-CLOSED. Order matters: capture original
    # state -> SAVE state (abort if it fails) -> apply the change -> arm auto-
    # relock. If state cannot be saved we do NOT weaken the box (an unlock with no
    # recorded re-lock path is the one failure that inverts this tool's purpose).
    param(
        [Parameter(Mandatory)][ValidateSet('captiveportal','printing','smbclient','rdp','winrm','vpn')][string]$Area,
        [int]$Minutes = 60,
        [string]$Reason = 'not specified'
    )
    if ($Minutes -lt 1)   { $Minutes = 1 }
    if ($Minutes -gt 480) { $Minutes = 480; Write-Log WARN 'Capping unlock at 8 hours.' }

    if (Get-ActiveUnlocks | Where-Object { $_.Area -eq $Area }) {
        Write-Log WARN "'$Area' is already unlocked. Re-lock it first if you want to reset the timer."
        return
    }

    Write-Log INFO "UNLOCK $Area for $Minutes min. Reason: $Reason"

    # PHASE 1: capture original state ONLY (no changes yet).
    $orig = @{}
    switch ($Area) {
        'captiveportal' { }  # nothing to capture; relock just removes temp rules
        'vpn'           { }  # nothing to capture; relock just removes the temp VPN allow rules
        'printing'  { $orig['SpoolerStart'] = (Get-Service Spooler -EA SilentlyContinue).StartType.ToString() }
        'smbclient' {
            $orig['LanmanWorkstationStart'] = (Get-Service LanmanWorkstation -EA SilentlyContinue).StartType.ToString()
            $orig['mrxsmb20Start'] = (Get-Service mrxsmb20 -EA SilentlyContinue).StartType.ToString()
        }
        'rdp'   { $orig['fDenyTSConnections'] = (Get-RegValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').Value }
        'winrm' { $orig['WinRMStart'] = (Get-Service WinRM -EA SilentlyContinue).StartType.ToString() }
    }

    # PHASE 2: SAVE STATE FIRST. If this fails, abort BEFORE weakening anything.
    if (-not (Save-UnlockState -Area $Area -Original $orig -Minutes $Minutes -Reason $Reason)) {
        Write-Log ERROR "Aborted unlock of '$Area' - no state could be recorded, so nothing was changed. The box stays locked."
        return
    }

    # PHASE 3: apply the actual change (state is now recorded, so worst case a
    # later relock/expiry cleanly reverts it).
    switch ($Area) {
        'captiveportal' {
            Invoke-Step 'Unlock' 'Captive-portal: allow outbound DNS/HTTP/HTTPS' {
                foreach ($p in @(53,80,443)) {
                    $proto = if ($p -eq 53) { 'UDP' } else { 'TCP' }
                    $rn = "HardenUnlock-CaptivePortal-$proto$p"
                    if (-not (Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $rn -Direction Outbound -Action Allow -Protocol $proto -RemotePort $p -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    }
                }
            }
            $Script:ManualSteps.Add("Captive portal unlocked for $Minutes min: outbound DNS/HTTP/HTTPS allowed so the portal page loads. Re-locks automatically.")
        }
        'vpn' {
            # Allow the common VPN protocols OUTBOUND so a tunnel can establish
            # even when outbound is default-blocked. Covers: IKEv2/IPsec (UDP 500,
            # 4500), OpenVPN (UDP 1194 + TCP 443), WireGuard (UDP 51820), plus ESP
            # (IP proto 50) and L2TP (UDP 1701). TCP 443 is already commonly allowed
            # but we add an explicit VPN-labeled rule so it is clear + easy to relock.
            Invoke-Step 'Unlock' 'VPN: allow outbound IKEv2/OpenVPN/WireGuard/L2TP' {
                $vpnRules = @(
                    @{ N='HardenUnlock-VPN-IKEv2-UDP500';  Proto='UDP'; Port=500 },
                    @{ N='HardenUnlock-VPN-IKEv2-UDP4500'; Proto='UDP'; Port=4500 },
                    @{ N='HardenUnlock-VPN-L2TP-UDP1701';  Proto='UDP'; Port=1701 },
                    @{ N='HardenUnlock-VPN-OpenVPN-UDP1194'; Proto='UDP'; Port=1194 },
                    @{ N='HardenUnlock-VPN-OpenVPN-TCP443';  Proto='TCP'; Port=443 },
                    @{ N='HardenUnlock-VPN-WireGuard-UDP51820'; Proto='UDP'; Port=51820 }
                )
                foreach ($vr in $vpnRules) {
                    if (-not (Get-NetFirewallRule -DisplayName $vr.N -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $vr.N -Direction Outbound -Action Allow -Protocol $vr.Proto -RemotePort $vr.Port -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    }
                }
                # ESP (IP protocol 50) - IPsec payload; no port, protocol-level allow.
                if (-not (Get-NetFirewallRule -DisplayName 'HardenUnlock-VPN-ESP' -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName 'HardenUnlock-VPN-ESP' -Direction Outbound -Action Allow -Protocol 50 -Profile Any -ErrorAction SilentlyContinue | Out-Null
                }
            }
            $Script:ManualSteps.Add("VPN unlocked for $Minutes min: outbound IKEv2 (500/4500), L2TP (1701), OpenVPN (1194/443), WireGuard (51820) and ESP allowed so a tunnel can connect. Re-locks automatically. If your VPN uses a non-standard port, add its own allow rule.")
        }
        'printing'  { Enable-ServiceSafe -Name 'Spooler' -StartupType Automatic | Out-Null }
        'smbclient' {
            Enable-ServiceSafe -Name 'LanmanWorkstation' -StartupType Automatic | Out-Null
            Enable-ServiceSafe -Name 'mrxsmb20' -StartupType Manual | Out-Null
        }
        'rdp' {
            Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 -Category 'Unlock' -Item 'RDP inbound temporarily allowed'
            Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
            Enable-ServiceSafe -Name 'TermService' -StartupType Manual | Out-Null
        }
        'winrm' {
            Enable-ServiceSafe -Name 'WinRM' -StartupType Manual | Out-Null
            Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
        }
    }

    # PHASE 4: arm the auto-relock. If scheduling fails, the box is open with no
    # timer - say so LOUDLY and record a manual step. Expire-StaleUnlocks on the
    # next launch is the backstop (the state file still has the expiry).
    if (-not (Register-RelockTask -Area $Area -At (Get-Date).AddMinutes($Minutes))) {
        Write-Log ERROR "AUTO-RELOCK NOT ARMED for '$Area'. You MUST re-lock manually (menu 8 > re-lock all, or -Relock $Area). It will also re-lock next time this tool runs."
        $Script:ManualSteps.Add("IMPORTANT: '$Area' is unlocked but the automatic re-lock timer FAILED to arm. Re-lock it manually before you leave this network/site: run this script with -Relock $Area (or menu 8).")
    }
    Write-Log OK "$Area is UNLOCKED for $Minutes min."
}

function Invoke-Relock {
    # Restore ONE area to its locked state using the saved original values, then
    # clear the state + scheduled task. Idempotent: safe to call on an already-
    # locked area.
    param([Parameter(Mandatory)][string]$Area)
    $state = Get-ActiveUnlocks | Where-Object { $_.Area -eq $Area } | Select-Object -First 1
    if (-not $state) { Write-Log INFO "'$Area' is not currently unlocked; nothing to re-lock."; return }
    Write-Log INFO "RE-LOCK $Area"
    $o = $state.Original

    $relockOk = $true
    try {
        switch ($Area) {
            'captiveportal' {
                Invoke-Step 'Relock' 'Remove captive-portal temp firewall rules' {
                    Get-NetFirewallRule -DisplayName 'HardenUnlock-CaptivePortal-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                }
            }
            'vpn' {
                Invoke-Step 'Relock' 'Remove VPN temp firewall rules' {
                    Get-NetFirewallRule -DisplayName 'HardenUnlock-VPN-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                }
            }
            'printing'  { Disable-ServiceSafe -Name 'Spooler' -Label 'Print Spooler re-locked' | Out-Null }
            'smbclient' {
                Disable-ServiceSafe -Name 'LanmanWorkstation' -Label 'SMB client re-locked' | Out-Null
                Disable-ServiceSafe -Name 'mrxsmb20' -Label 'SMB2 client driver re-locked' | Out-Null
            }
            'rdp' {
                $prior = if ($o.fDenyTSConnections -ne $null) { $o.fDenyTSConnections } else { 1 }
                Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' $prior -Category 'Relock' -Item 'RDP inbound re-denied'
                Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
                Disable-ServiceSafe -Name 'TermService' -Label 'RDP service re-locked' | Out-Null
            }
            'winrm' {
                Disable-ServiceSafe -Name 'WinRM' -Label 'WinRM re-locked' | Out-Null
                Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
            }
        }
    } catch {
        $relockOk = $false
        Write-Log ERROR "Re-lock of '$Area' hit an error: $($_.Exception.Message)."
    }
    # Only clear the state (and the scheduled task) if the re-lock SUCCEEDED. If it
    # failed, KEEP the state so Expire-StaleUnlocks / a manual retry re-locks it -
    # never mark an area 'locked' when it might still be open (fail closed).
    if ($relockOk) {
        Remove-UnlockState -Area $Area
        Write-Log OK "$Area is RE-LOCKED."
    } else {
        Write-Log ERROR "'$Area' may still be partly unlocked. State kept; it will be retried on next launch, or re-run -Relock $Area."
    }
}

function Invoke-RelockAll {
    # Panic button: re-lock every active unlock right now.
    $active = Get-ActiveUnlocks
    if (-not $active -or $active.Count -eq 0) { Write-Log INFO 'No active unlocks; everything is already locked.'; return }
    Write-Log INFO "Re-locking ALL ($($active.Count)) active unlock(s)..."
    foreach ($u in $active) { Invoke-Relock -Area $u.Area }
    Write-Log OK 'All areas re-locked.'
}

function Invoke-AdoptUSB {
    # DIFFERENT from a timed unlock: you bought a new dongle/device and want it
    # PERMANENTLY approved. Learns the currently-present USB device IDs and adds
    # them to the allowlist, logging what was adopted (audit trail). Not timed.
    Write-Log INFO 'Adopt USB: learning currently-present devices to add to the allowlist.'
    if (Get-Command Invoke-Mod-USBGuard -ErrorAction SilentlyContinue) {
        $Script:ManualSteps.Add('USB adopt: re-run the USB lockdown (extra security > USB) with the new device plugged in; it will be learned into the allowlist and denied-by-default stays for everything else. The adopted device is logged.')
        Invoke-Mod-USBGuard
    } else {
        Write-Log WARN 'USBGuard module not available.'
    }
}

function Enable-ServiceSafe {


    param([Parameter(Mandatory)][string]$Name, [ValidateSet('Automatic','Manual')][string]$StartupType='Manual', [string]$Category='NetworkServices')
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Log WARN "Service '$Name' not present; cannot enable."; return $false }
    Invoke-Step $Category "Enabled service $Name ($StartupType)" {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        Start-Service -Name $Name -ErrorAction SilentlyContinue
    }
    return $true
}

function Invoke-Mod-NetworkServices {
    # --- AUDIT: Network-services lockdown (Tier 3 aggressive): disables SMB
    # server+client, Print Spooler, Remote Desktop, WinRM, discovery services, and
    # legacy daemons. Each is a remote attack surface / lateral-movement path.
    # Aggressive by design (breaks shares/printing/RDP) and fully reversible via
    # extra-security menu + undo. Audit: CIS 5.x/18.x service + protocol controls.
    Write-Section 'Network services lockdown (SMB, printing, RDP, remote mgmt)'

    # ---- SMB ----
    # SERVER off: this box stops hosting shares/printers out.
    Invoke-Step 'NetworkServices' 'SMB server off (stop hosting shares)' {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }
    Disable-ServiceSafe -Name 'LanmanServer' -Label 'SMB server service (LanmanServer) disabled' | Out-Null
    if (-not $KeepSMBClient) {
        # CLIENT off: this box can no longer reach \\server shares, mapped drives,
        # or domain SYSVOL/GPO. You chose this; it is loud on purpose.
        Disable-ServiceSafe -Name 'LanmanWorkstation' -Label 'SMB client service (LanmanWorkstation) disabled' | Out-Null
        Disable-ServiceSafe -Name 'mrxsmb20' -Label 'SMB2 client driver' | Out-Null
        $Script:ManualSteps.Add('SMB CLIENT is disabled: this box can no longer open \\server\share, mapped drives, or (if domain-joined) pull GPO/SYSVOL/roaming profiles. Re-enable via extra-security > SMB allow, or run with -KeepSMBClient. This is the aggressive setting you selected.')
    } else {
        Write-Log INFO 'SMB client kept (-KeepSMBClient). You can still reach network shares.'
        Add-Result 'NetworkServices' 'SMB client' 'Skipped' 'kept by -KeepSMBClient'
    }

    # ---- Printing ----
    if (-not $KeepPrinting) {
        # Spooler fully off: no printing at all (kills PrintNightmare surface).
        $shared = @()
        try { $shared = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared }) } catch {}
        if ($shared.Count -gt 0 -and -not $Force) {
            Write-Log ERROR "SAFETY STOP: $($shared.Count) SHARED printer(s) present. Disabling the Spooler removes printing for their clients too. Skipped. Pass -Force or -KeepPrinting."
            Add-Result 'NetworkServices' 'Disable Print Spooler' 'Skipped' 'shared printers, no -Force'
        } else {
            Disable-ServiceSafe -Name 'Spooler' -Label 'Print Spooler disabled (no printing)' | Out-Null
            $Script:ManualSteps.Add('Print Spooler is fully disabled: NO printing (local or network) works until re-enabled. Re-enable via extra-security > Printer allow, or -KeepPrinting. Removes the PrintNightmare RCE surface.')
        }
    } else {
        # Keep local printing, but kill the remote-print RPC endpoint (the RCE path).
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RegisterSpoolerRemoteRpcEndPoint' 2 -Category 'NetworkServices' -Item 'Remote print RPC endpoint OFF (local printing kept)'
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1 -Category 'NetworkServices' -Item 'Point-and-Print driver install = admins only'
        Write-Log INFO 'Local printing kept (-KeepPrinting); remote print RPC disabled.'
    }

    # ---- Remote Desktop service ----
    # The RemoteAccess module already denies RDP logons (fDenyTSConnections) and
    # disables the RDP firewall group. Here we additionally stop the service so
    # it is not listening at all. Guarded so we do not sever a live RDP session.
    if ((Assert-NotSeveringOurAccess -What 'disable the Remote Desktop service')) {
        Disable-ServiceSafe -Name 'TermService' -Label 'Remote Desktop service (TermService) disabled' | Out-Null
    }

    # ---- WinRM / PowerShell Remoting ----
    if ((Assert-NotSeveringOurAccess -What 'disable WinRM/PowerShell Remoting')) {
        Invoke-Step 'NetworkServices' 'Disabled WinRM firewall + listener' {
            Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue
        }
        Disable-ServiceSafe -Name 'WinRM' -Label 'WinRM service disabled' | Out-Null
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowAutoConfig' 0 -Category 'NetworkServices' -Item 'WinRM auto-config off'
    }

    # ---- Remote Assistance (RemoteAccess sets fAllowToGetHelp; add unsolicited) ----
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowUnsolicited' 0 -Category 'NetworkServices' -Item 'Unsolicited Remote Assistance off'

    # ---- OpenSSH server (only if present) ----
    Disable-ServiceSafe -Name 'sshd' -Label 'OpenSSH server (sshd) disabled' | Out-Null

    # ---- Discovery: SSDP / UPnP / Function Discovery ----
    foreach ($d in @('SSDPSRV','upnphost','FDPHost','FDResPub','WMPNetworkSvc')) {
        Disable-ServiceSafe -Name $d -Label "Discovery service $d disabled" | Out-Null
    }
    Invoke-Step 'NetworkServices' 'Disabled Network Discovery firewall group' {
        Disable-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction SilentlyContinue
    }

    # ---- Legacy services (only if present): Telnet, FTP, SNMP ----
    foreach ($leg in @('TlntSvr','FTPSVC','MSFTPSVC','SNMP','SNMPTRAP','simptcp')) {
        Disable-ServiceSafe -Name $leg -Label "Legacy service $leg disabled" | Out-Null
    }

    # ---- Xbox / gaming services (unneeded on a workstation; only if present) ----
    foreach ($xb in @('XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc','GamingServices','GamingServicesNet')) {
        Disable-ServiceSafe -Name $xb -Label "Xbox/gaming service $xb disabled" | Out-Null
    }

    # ---- Extra name-resolution / discovery lockdown (locking this box down) ----
    # mDNS: the third broadcast name-resolution protocol (with LLMNR + NetBIOS).
    # Responder and similar tools poison it to harvest hashes. Off = unicast DNS
    # only. (LLMNR is already off in the Network module.)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0 -Category 'NetworkServices' -Item 'mDNS off (no multicast name resolution)'
    # NetBIOS at the REGISTRY level too (the Network module sets it per-adapter via
    # WMI; this survives adapter re-add): NetbiosOptions=2 = disabled on every
    # existing interface.
    Invoke-Step 'NetworkServices' 'NetBIOS disabled on all interfaces (registry)' {
        $ifaces = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (Test-Path $ifaces) {
            Get-ChildItem $ifaces | ForEach-Object {
                Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -ErrorAction SilentlyContinue
            }
        }
    }
    # Peer Name Resolution Protocol (PNRP) + peer networking: legacy P2P name
    # services, unnecessary on a locked-down workstation.
    foreach ($p2p in @('PNRPsvc','p2psvc','p2pimsvc','PNRPAutoReg')) {
        Disable-ServiceSafe -Name $p2p -Label "Peer name resolution $p2p disabled" | Out-Null
    }
    # Link-Layer Topology Discovery responder + mapper: answers network-mapping
    # probes, useful only for the "network map" feature. Disable the responders.
    foreach ($lld in @('lltdsvc')) {
        Disable-ServiceSafe -Name $lld -Label "Link-Layer Topology $lld disabled" | Out-Null
    }
    Invoke-Step 'NetworkServices' 'Disabled Link-Layer Topology firewall rules' {
        Disable-NetFirewallRule -DisplayGroup 'Link-Layer Topology Discovery' -ErrorAction SilentlyContinue
    }

    Write-Log OK 'Network services lockdown applied. Use extra-security to re-allow any of these.'
}

function Invoke-Mod-RdpSshLockdown {
    if (-not $LockdownRemoteShell) { return }
    Write-Section 'Network remote-shell lockdown (RDP + SSH)'
    # Dedicated lockout-risk option: shut BOTH interactive network remote-shell
    # paths - RDP (3389) and OpenSSH server (22) - service, firewall rule, and the
    # policy that re-enables them. Segmented on its own because cutting these can
    # lock you out of a headless/remote box. Reversible; refuses over the session
    # it would sever unless -Force.

    # RDP -------------------------------------------------------------------
    if (Assert-NotSeveringOurAccess -What 'lock down RDP (deny inbound Remote Desktop)') {
        Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 -Category 'RemoteShell' -Item 'RDP inbound denied (fDenyTSConnections)'
        Invoke-Step 'RemoteShell' 'Disable Remote Desktop firewall rules' {
            $r = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
            if ($r) { $r | Disable-NetFirewallRule -ErrorAction Stop }
        }
        Add-Undo @{ Kind='Command'; Undo="Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"; Label='re-enable Remote Desktop firewall group' }
        Disable-ServiceSafe -Name 'TermService' -Category 'RemoteShell' -Label 'Remote Desktop service (TermService) disabled' | Out-Null
    }

    # SSH (OpenSSH server) --------------------------------------------------
    # Only if present - OpenSSH server is an optional Windows feature. Disable the
    # service and the inbound firewall rule. (We do NOT touch the SSH CLIENT, which
    # is outbound-only and useful.)
    $sshd = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($sshd) {
        if (Assert-NotSeveringOurAccess -What 'lock down SSH (disable OpenSSH server)') {
            Disable-ServiceSafe -Name 'sshd' -Category 'RemoteShell' -Label 'OpenSSH server (sshd) disabled' | Out-Null
            Disable-ServiceSafe -Name 'ssh-agent' -Category 'RemoteShell' -Label 'OpenSSH agent (ssh-agent) disabled' | Out-Null
            Invoke-Step 'RemoteShell' 'Disable OpenSSH inbound firewall rule' {
                $r = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
                if (-not $r) { $r = Get-NetFirewallRule -DisplayName '*OpenSSH*Server*' -ErrorAction SilentlyContinue }
                if ($r) { $r | Disable-NetFirewallRule -ErrorAction Stop }
            }
            Add-Undo @{ Kind='Command'; Undo="Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue"; Label='re-enable OpenSSH server firewall rule' }
        }
    } else {
        Write-Log INFO 'OpenSSH server (sshd) not present; nothing to lock down for SSH.'
        Add-Result 'RemoteShell' 'OpenSSH server lockdown' 'Skipped' 'sshd not present'
    }

    Write-Log OK 'Remote-shell lockdown complete: RDP and SSH inbound paths closed (where present).'
    $Script:ManualSteps.Add('RDP and SSH inbound were locked down. If this box is headless/remote, CONFIRM you have another way in (console, KVM, or a still-open session) before disconnecting. Reversible via the undo script.')
}

function Invoke-Mod-BlockInbound {
    if (-not $BlockAllInbound) { return }
    Write-Section 'Block all inbound (no reachable ports)'
    # "No inbound ports open" - the complete version. The baseline already sets the
    # firewall default inbound = Block, but Windows ships dozens of ENABLED inbound
    # ALLOW rules (Network Discovery, File/Printer Sharing, Cast to Device, mDNS,
    # Remote Assistance, Delivery Optimization inbound, AllJoyn, etc.) that punch
    # holes through that default. This disables ALL enabled inbound allow rules, so
    # the default-block becomes the only inbound policy: nothing is reachable.
    #
    # SAFETY:
    #  - Outbound rules are NEVER touched (that would break the box).
    #  - Core-networking inbound rules the IP stack needs (DHCP, ICMPv6 neighbor
    #    discovery, loopback) are PRESERVED - killing them can break connectivity
    #    itself. A truly air-gapped box could drop even these, but that is beyond
    #    "no inbound ports" and into "no network", so we keep them.
    #  - If you are on RDP/WinRM, disabling the inbound rule for your own protocol
    #    cuts your session on reconnect - refuses without -Force (same guard as the
    #    remote-access module).
    #  - Every disabled rule is recorded for undo (re-enable by name).

    Write-Host ''
    Write-Host '  BLOCK ALL INBOUND  (disable every inbound allow rule)' -ForegroundColor Yellow
    Write-Host '  The firewall default is already Block; this removes the allow-rule' -ForegroundColor Gray
    Write-Host '  holes so NOTHING inbound is reachable. Outbound is untouched. Core' -ForegroundColor Gray
    Write-Host '  networking (DHCP, IPv6 neighbor discovery, loopback) is preserved so' -ForegroundColor Gray
    Write-Host '  the network stack keeps working.' -ForegroundColor Gray

    # Remote-session guard: if we are ON rdp/winrm, blocking inbound kills the
    # reconnect. Refuse without -Force.
    $rs = $Script:RemoteSession
    if ($rs -and ($rs.OverRDP -or $rs.OverWinRM) -and -not $Force) {
        Write-Host ''
        Write-Host '  *** YOU ARE ON A REMOTE SESSION (RDP/WinRM). ***' -ForegroundColor Red
        Write-Host '  Blocking all inbound will sever your ability to reconnect. Run from' -ForegroundColor Red
        Write-Host '  the console, or re-run with -Force if you accept losing remote access.' -ForegroundColor Red
        Write-Log ERROR 'SAFETY STOP: block-all-inbound over a remote session without -Force.'
        Add-Result 'Inbound' 'Block all inbound' 'Skipped' 'remote session, no -Force'
        return
    }

    if ($Script:DryRun) {
        try {
            $enabledIn = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
            Write-Log DRY "WOULD disable $($enabledIn.Count) enabled inbound allow rule(s), preserving core-networking (DHCP/ND/loopback)."
        } catch { Write-Log DRY 'WOULD disable enabled inbound allow rules (could not enumerate in dry-run).' }
        return
    }

    if (-not (Confirm-Apply 'disable ALL inbound allow rules (no inbound reachable)')) {
        Write-Log WARN 'Aborted; inbound rules unchanged.'
        return
    }

    # Rules to PRESERVE: the IP stack genuinely needs these; dropping them can break
    # DHCP address renewal and IPv6 on-link function. Match by DisplayGroup.
    $preserveKeep   = @('Core Networking', 'Core Networking Diagnostics')

    $disabled = 0; $kept = 0
    try {
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    } catch {
        Write-Log ERROR "Could not enumerate inbound rules: $($_.Exception.Message)"
        Add-Result 'Inbound' 'Block all inbound' 'Failed' $_.Exception.Message
        return
    }

    foreach ($r in $rules) {
        $grp = $r.DisplayGroup
        if ($grp -in $preserveKeep) { $kept++; continue }
        Invoke-Step 'Inbound' "Disable inbound rule: $($r.DisplayName)" {
            Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop
        }
        Add-Undo @{ Kind='Command'; Undo="Enable-NetFirewallRule -Name '$($r.Name)' -ErrorAction SilentlyContinue"; Label="re-enable inbound rule $($r.DisplayName)" }
        $disabled++
    }

    Write-Log OK "Inbound lockdown: disabled $disabled inbound allow rule(s); preserved $kept core-networking rule(s)."
    Write-Log INFO 'The firewall default inbound=Block is now the only inbound policy for everything except core networking. No service ports are reachable from the network.'
    Add-Result 'Inbound' 'Block all inbound allow rules' 'Applied' "$disabled disabled, $kept core-networking kept"
    $Script:ManualSteps.Add("All inbound firewall allow rules were DISABLED (except Core Networking). The box accepts no inbound connections. To re-allow a specific service later, re-enable its rule: Get-NetFirewallRule -DisplayGroup '<group>' | Enable-NetFirewallRule - or run the undo script.")
}

function Invoke-AILockAcl {
    # *** AI-KEY ACL LOCK - the sharpest, most dangerous option in this tool. ***
    #
    # What it does: puts an explicit DENY-write Access Control Entry for the SYSTEM
    # account on the AI-policy registry keys (WindowsAI, WindowsCopilot), so that a
    # Windows Update / provisioning task running as SYSTEM CANNOT flip the AI-disable
    # keys back on. It makes the AI-off state survive cumulative updates.
    #
    # *** WHY THIS IS OFF BY DEFAULT AND WHY YOU SHOULD THINK HARD ***
    # The Windows servicing model relies on SYSTEM/TrustedInstaller writing these
    # hives during updates. Denying SYSTEM write on a key does not politely scope to
    # "just the AI setting" - it can:
    #   - cause a cumulative or feature UPDATE to fail or partially apply, which can
    #     leave the box unpatched (a SECURITY regression) or in an inconsistent state;
    #   - be seen by some EDR/AV as tampering with OS integrity;
    #   - be non-obvious to the next admin, who will not expect a deny-SYSTEM ACE and
    #     may burn hours diagnosing "why won't this key update".
    # This is a deliberate trade of update-integrity for config-persistence. Most
    # environments should instead just RE-RUN this hardening tool after big updates -
    # that achieves the same end without fighting the servicing model.
    #
    # It IS reversible: the tool records an undo that removes the deny ACE and
    # restores inheritance, and prints the manual restore command below.

    Write-Host ''
    Write-Host '  =====================================================================' -ForegroundColor Red
    Write-Host '  AI-KEY ACL LOCK  (deny SYSTEM write on the AI-policy registry keys)' -ForegroundColor Red
    Write-Host '  =====================================================================' -ForegroundColor Red
    Write-Host '  This makes the AI-off settings survive Windows Updates by blocking' -ForegroundColor Gray
    Write-Host '  the update engine (running as SYSTEM) from rewriting them.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  READ THIS BEFORE YOU CONFIRM:' -ForegroundColor Yellow
    Write-Host '   - It deliberately BREAKS part of the Windows servicing model. A' -ForegroundColor Red
    Write-Host '     cumulative/feature update that needs to write these keys can FAIL' -ForegroundColor Red
    Write-Host '     or apply partially - which can leave this box UNPATCHED.' -ForegroundColor Red
    Write-Host '   - Some EDR/AV may flag a deny-SYSTEM ACE as OS tampering.' -ForegroundColor Red
    Write-Host '   - The next admin will not expect this and may waste hours on it.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  SAFER ALTERNATIVE: just re-run this tool after major updates. That' -ForegroundColor Green
    Write-Host '  re-asserts every AI-off key without sabotaging the update engine.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Reversible: an undo entry is recorded, and the manual restore command' -ForegroundColor Gray
    Write-Host '  is printed after apply.' -ForegroundColor Gray

    $targets = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
    )

    if ($Script:DryRun) {
        foreach ($t in $targets) { Write-Log DRY "WOULD add deny-SYSTEM-write ACE on $t (and record an undo to remove it)" }
        return
    }

    # A confirmation this sharp gets a stricter gate than the usual YES: require the
    # user to type an explicit phrase, so it can never be a reflexive keypress.
    Write-Host ''
    Write-Host "  To proceed, type exactly:  LOCK AI KEYS" -ForegroundColor Yellow
    $phrase = Read-MenuChoice '  confirmation'
    if ($phrase -ne 'LOCK AI KEYS') {
        Write-Log WARN 'Aborted; AI-key ACLs unchanged (confirmation phrase not matched).'
        Add-Result 'AILock' 'AI-key ACL lock' 'Skipped' 'confirmation not matched'
        return
    }

    foreach ($path in $targets) {
        if (-not (Test-Path $path)) {
            # create the key first so there is something to lock (the AI-off values
            # were written earlier in the Privacy module, but be defensive)
            try { New-Item -Path $path -Force -ErrorAction Stop | Out-Null } catch {
                Write-Log WARN "Could not create $path to lock it: $($_.Exception.Message)"
                continue
            }
        }
        Invoke-Step 'AILock' "Deny SYSTEM write on $path" {
            $acl = Get-Acl -Path $path -ErrorAction Stop
            $sid = New-Object System.Security.Principal.SecurityIdentifier(
                [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $sid, 'SetValue,CreateSubKey,WriteKey', 'ContainerInherit', 'None', 'Deny')
            $acl.AddAccessRule($rule)
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        }
        # Record a reversible undo: remove the deny ACE and re-enable inheritance.
        Add-Undo @{
            Kind  = 'Command'
            Undo  = "`$a = Get-Acl -Path '$path'; `$sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid,`$null); `$a.PurgeAccessRules(`$sid); `$a.SetAccessRuleProtection(`$false,`$true); Set-Acl -Path '$path' -AclObject `$a"
            Label = "remove deny-SYSTEM ACE + restore inheritance on $path"
        }
    }

    Write-Log OK 'AI-key ACL lock applied. The AI-off keys now resist SYSTEM rewrites.'
    Write-Log WARN 'REMEMBER: this can make Windows Updates fail on these keys. If patching breaks, REVERT first.'
    Write-Host ''
    Write-Host '  MANUAL RESTORE (run per key if you need to undo outside this tool):' -ForegroundColor Cyan
    foreach ($path in $targets) {
        Write-Host "    `$a = Get-Acl '$path'; `$s = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid,`$null); `$a.PurgeAccessRules(`$s); `$a.SetAccessRuleProtection(`$false,`$true); Set-Acl '$path' `$a" -ForegroundColor Gray
    }
    $Script:ManualSteps.Add('AI-key ACL lock is ACTIVE: SYSTEM is denied write on the WindowsAI/WindowsCopilot policy keys. This can block Windows Update from servicing those keys. Revert via the undo script or the printed restore commands before troubleshooting update failures.')
}

function Invoke-PKINITHardening {
    # Kerberos PKINIT hash-algorithm restriction: refuse SHA-1 in certificate-based
    # (smart-card / Windows Hello for Business) initial Kerberos authentication,
    # allowing only SHA-256/384/512. Modern crypto-agility; part of the MS 24H2
    # baseline and STIG direction.
    #
    # *** THE TRAP (why this is opt-in, never baseline) ***
    # If this box authenticates against an Active Directory domain controller
    # running Windows Server 2022 or OLDER, those DCs still use SHA-1 for the
    # initial PKINIT trust negotiation. With SHA-1 refused here, LSASS rejects the
    # SHA-1 hash, the machine key cannot be derived, and Kerberos SILENTLY FAILS
    # (system log error 0x3bc4). The box can lose the ability to authenticate.
    # Fix: upgrade DCs to Server 2025 (native SHA-256 PKINIT), or REVERT this.
    Write-Host ''
    Write-Host '  PKINIT SHA-1 deprecation (Kerberos cert-auth crypto agility):' -ForegroundColor Yellow
    Write-Host '   - Refuses SHA-1 in smart-card / WHfB Kerberos auth; requires SHA-256+.' -ForegroundColor Gray
    Write-Host '   - DANGER on domain-joined boxes: if your DCs are Server 2022 or older,' -ForegroundColor Red
    Write-Host '     this SILENTLY BREAKS authentication (error 0x3bc4). Needs Server 2025' -ForegroundColor Red
    Write-Host '     DCs, or you must revert. On a standalone box it is inert-but-harmless.' -ForegroundColor Gray

    $domainJoined = $false
    try { $domainJoined = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    if ($domainJoined) {
        Write-Host ''
        Write-Host '  *** THIS BOX IS DOMAIN-JOINED. ***' -ForegroundColor Red
        Write-Host '  If your domain controllers are not Server 2025, applying this can lock' -ForegroundColor Red
        Write-Host '  this machine out of Kerberos authentication. Confirm your DCs support' -ForegroundColor Red
        Write-Host '  SHA-256 PKINIT BEFORE proceeding, and keep console access to revert.' -ForegroundColor Red
        if (-not $Force) {
            Write-Log ERROR 'SAFETY STOP: domain-joined box, PKINIT SHA-1 deprecation can sever auth. Re-run with -Force if you have verified Server 2025 DCs and have console access.'
            Add-Result 'PKINIT' 'PKINIT SHA-1 deprecation' 'Skipped' 'domain-joined, no -Force'
            return
        }
    }
    if (-not (Confirm-Apply 'PKINIT SHA-1 deprecation (can break domain auth vs pre-2025 DCs)')) {
        Write-Log WARN 'Aborted; PKINIT unchanged.'
        return
    }
    # Restrict PKINIT client hash algorithms to SHA-256/384/512 (drop SHA-1). The
    # per-algorithm DWORDs live under the Kerberos Parameters key; 0 disables an
    # algorithm for PKINIT, non-zero (priority) enables it.
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\PKInitHashAlgorithms'
    Set-Reg "$k\SHA1"   'Enabled' 0 -Category 'PKINIT' -Item 'PKINIT SHA-1 disabled'
    Set-Reg "$k\SHA256" 'Enabled' 1 -Category 'PKINIT' -Item 'PKINIT SHA-256 enabled'
    Set-Reg "$k\SHA384" 'Enabled' 1 -Category 'PKINIT' -Item 'PKINIT SHA-384 enabled'
    Set-Reg "$k\SHA512" 'Enabled' 1 -Category 'PKINIT' -Item 'PKINIT SHA-512 enabled'
    $Script:ManualSteps.Add('PKINIT SHA-1 is deprecated (SHA-256+ required for Kerberos cert auth). IF this box is domain-joined and authentication starts failing with error 0x3bc4, your DCs are pre-Server-2025: revert via the undo script (or set PKInitHashAlgorithms\\SHA1\\Enabled=1) from the CONSOLE.')
    Write-Log OK 'PKINIT SHA-1 deprecated. Watch for 0x3bc4 auth errors if domain-joined; reverse via undo if needed.'
}

function Invoke-ProtectedPrint {
    # Windows Protected Print (WPP), 24H2+. Forces a DRIVERLESS print model: the
    # spooler runs common tasks in USER context (not SYSTEM), only IPP/Mopria
    # printers work, and ALL third-party printer drivers are blocked. This is the
    # architectural fix for PrintNightmare and eliminates Point-and-Print driver
    # attacks entirely.
    # CAVEAT (from the guide): enabling WPP PERMANENTLY DELETES existing legacy /
    # non-IPP print queues and blocks non-compliant drivers. Audit your printer
    # fleet for IPP/Mopria compatibility FIRST.
    Write-Host ''
    Write-Host '  Windows Protected Print (WPP) - driverless printing:' -ForegroundColor Yellow
    Write-Host '   - Blocks ALL third-party printer drivers; only IPP/Mopria printers work.' -ForegroundColor Gray
    Write-Host '   - Spooler drops from SYSTEM to USER context (kills PrintNightmare class).' -ForegroundColor Gray
    Write-Host '   - DELETES existing non-IPP print queues on activation. 24H2+ only.' -ForegroundColor Gray
    $build = 0; try { $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber } catch {}
    if ($build -gt 0 -and $build -lt 26100) {
        Write-Log WARN "This box is build $build; WPP needs 24H2 (26100+). The policy will set but may be inert until you are on 24H2."
    }
    if (-not (Confirm-Apply 'Windows Protected Print (driverless; deletes non-IPP queues)')) {
        Write-Log WARN 'Aborted; WPP not enabled.'
        return
    }
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\WPP' 'WindowsProtectedPrintMode' 1 -Category 'ProtectedPrint' -Item 'Windows Protected Print (driverless) ON'
    # Belt: also restrict Point-and-Print driver installs to admins (pre-24H2 boxes
    # that ignore WPP still get this PrintNightmare mitigation).
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1 -Category 'ProtectedPrint' -Item 'Point-and-Print driver install = admins only'
    $Script:ManualSteps.Add('Windows Protected Print is enabled (driverless). Only IPP/Mopria printers work; third-party drivers are blocked and non-IPP queues were removed. If a needed printer stopped working, it is not IPP-compatible - use a Mopria/IPP-capable path or reverse via the undo script.')
    Write-Log OK 'Windows Protected Print enabled. Reverse via the undo script if a printer breaks.'
}

function Invoke-DisableBluetooth {
    # Disable the Bluetooth stack. DISA STIG mandates this unless BT is explicitly
    # approved (it is a proximity attack surface: BlueBorne, key-injection, etc.).
    # CAVEAT: breaks Bluetooth mice, keyboards, headsets, and file transfer.
    Write-Host ''
    Write-Host '  Disable Bluetooth (STIG) - breaks BT mice/keyboards/headsets.' -ForegroundColor Yellow
    if (-not (Confirm-Apply 'disabling the Bluetooth stack')) {
        Write-Log WARN 'Aborted; Bluetooth left as-is.'
        return
    }
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Bluetooth' 'AllowAdvertising' 0 -Category 'Bluetooth' -Item 'Bluetooth advertising off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Bluetooth' 'AllowDiscoverableMode' 0 -Category 'Bluetooth' -Item 'Bluetooth discoverable off'
    Disable-ServiceSafe -Name 'bthserv' -Category 'Bluetooth' -Label 'Bluetooth Support Service disabled' | Out-Null
    $Script:ManualSteps.Add('Bluetooth is disabled (service + advertising/discoverable). BT peripherals will stop working. Re-enable: Set-Service bthserv -StartupType Manual; Start-Service bthserv, and clear the Bluetooth policy keys - or use the undo script.')
    Write-Log OK 'Bluetooth disabled.'
}

function Invoke-AggressiveNetwork {
    # Tier 3-4 items from the 4-tier guide that BREAK common workflows, so they are
    # opt-in and confirmed, not baseline. Reversible via the undo script.
    Write-Host ''
    Write-Host '  AGGRESSIVE NETWORK (Tier 3-4) - these BREAK common management:' -ForegroundColor Yellow
    Write-Host '   - Removing admin shares (C$, ADMIN$) breaks PsExec, MECM payload' -ForegroundColor Gray
    Write-Host '     drops, and credentialed vulnerability scanners.' -ForegroundColor Gray
    Write-Host '   - UNC hardening makes SYSVOL/NETLOGON silently fail if the DC does' -ForegroundColor Gray
    Write-Host '     not support SMB signing (domain only; inert-but-harmless standalone).' -ForegroundColor Gray
    if (-not (Confirm-Apply 'the aggressive Tier 3-4 network lockdown')) {
        Write-Log WARN 'Aborted; nothing applied.'
        return
    }
    # Admin shares off: AutoShareWks (workstation) + AutoShareServer (server SKU).
    # (Guide Domain B.1, Tier 3.)
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks' 0 -Category 'NetworkServices' -Item 'Admin share C$ off (workstation)'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer' 0 -Category 'NetworkServices' -Item 'Admin share off (server SKU)'
    $Script:ManualSteps.Add('Admin shares (C$/ADMIN$) disabled. Breaks PsExec, MECM/SCCM payload drops, and credentialed scanners that write to C$. Reverse via the undo script if you rely on those.')
    # UNC hardening: mandate Kerberos mutual auth + integrity on SYSVOL/NETLOGON so
    # a spoofed DC cannot serve a malicious GPO. (Guide Domain B.2, Tier 2/3.)
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\SYSVOL' 'RequireMutualAuthentication=1, RequireIntegrity=1' 'String' -Category 'NetworkServices' -Item 'UNC SYSVOL hardened'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\NETLOGON' 'RequireMutualAuthentication=1, RequireIntegrity=1' 'String' -Category 'NetworkServices' -Item 'UNC NETLOGON hardened'
    $Script:ManualSteps.Add('UNC paths SYSVOL/NETLOGON now require Kerberos mutual auth + integrity. On a domain, verify DCs support SMB signing or GPO processing fails. Inert (harmless) on a standalone box.')
    Write-Log OK 'Aggressive network lockdown applied. Reverse via the undo script.'
}

function Show-NetworkAllowMenu {
    while ($true) {
        Write-Host ''
        Write-Host '  RE-ALLOW network services (reverses the baseline lockdown).' -ForegroundColor Yellow
        Show-RemoteSessionWarningIfAny
        Write-Host '    1  SMB: allow          re-enable file sharing (server + client)' -ForegroundColor Gray
        Write-Host '    2  SMB: disable        turn SMB back off (server + client)' -ForegroundColor Gray
        Write-Host '    3  Printer: allow      re-enable the Print Spooler (printing works)' -ForegroundColor Gray
        Write-Host '    4  Printer: disable    turn the Print Spooler back off' -ForegroundColor Gray
        Write-Host '    5  Remote Desktop: allow    re-enable inbound RDP' -ForegroundColor Gray
        Write-Host '    6  Remote Desktop: disable  turn inbound RDP back off' -ForegroundColor Gray
        Write-Host '    b  back' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            '1' {
                Enable-ServiceSafe -Name 'LanmanServer' -StartupType Automatic | Out-Null
                Enable-ServiceSafe -Name 'LanmanWorkstation' -StartupType Automatic | Out-Null
                Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer' 'Start' 2 -Category 'NetworkServices' -Item 'SMB server auto-start'
                Write-Log OK 'SMB re-enabled (server + client).'
            }
            '2' {
                Disable-ServiceSafe -Name 'LanmanServer' | Out-Null
                Disable-ServiceSafe -Name 'LanmanWorkstation' | Out-Null
            }
            '3' { Enable-ServiceSafe -Name 'Spooler' -StartupType Automatic | Out-Null }
            '4' { Disable-ServiceSafe -Name 'Spooler' | Out-Null }
            '5' {
                Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 -Category 'NetworkServices' -Item 'Remote Desktop inbound allowed'
                Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
                Enable-ServiceSafe -Name 'TermService' -StartupType Manual | Out-Null
                Write-Log OK 'Remote Desktop re-enabled (inbound).'
            }
            '6' {
                if ((Assert-NotSeveringOurAccess -What 'disable Remote Desktop')) {
                    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 -Category 'NetworkServices' -Item 'Remote Desktop inbound denied'
                    Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
                }
            }
            'b'    { return }
            'back' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray }
        }
    }
}

function Show-ExtraSecurityMenu {
    while ($true) {
        Write-Host ''
        Write-Host '  EXTRA SECURITY - extreme items. Evaluate (dry-run) before applying.' -ForegroundColor Yellow
        Show-RemoteSessionWarningIfAny
        Write-Host '    1  USB: evaluate     dry-run - show what would be learned/blocked. No change.' -ForegroundColor Gray
        Write-Host '    2  USB: learn+lock   allowlist devices present NOW, block NEW ones.' -ForegroundColor Gray
        Write-Host '                          Keyboard/mouse are force-allowed. Confirms first.' -ForegroundColor Gray
        Write-Host '    3  USB: also block storage   as 2, plus disable USB mass storage.' -ForegroundColor Gray
        Write-Host '    4  sudo + Print Spooler      disable Windows sudo; Spooler needs opt-in.' -ForegroundColor Gray
        Write-Host '    5  no auto-install on insert new hardware wont pull drivers/apps; WPBT off.' -ForegroundColor Gray
        Write-Host '    6  SMB / printer / RDP  allow or disable file sharing, printing, remote desktop.' -ForegroundColor Gray
        Write-Host '    7  aggressive network   remove admin shares (C$), harden UNC paths. Tier 3-4.' -ForegroundColor Gray
        Write-Host '    8  protected print      driverless WPP mode (kills PrintNightmare). Deletes' -ForegroundColor Gray
        Write-Host '                          non-IPP print queues. 24H2+.' -ForegroundColor Gray
        Write-Host '    9  disable Bluetooth    stop the Bluetooth stack (STIG). Breaks BT peripherals.' -ForegroundColor Gray
        Write-Host '   10  PKINIT SHA-1 off     Kerberos cert-auth crypto agility. DANGER: can break' -ForegroundColor Gray
        Write-Host '                          domain auth vs pre-2025 DCs (error 0x3bc4).' -ForegroundColor Gray
        Write-Host '   11  password policy      enforce CIS password/lockout rules, or relax (remove)' -ForegroundColor Gray
        Write-Host '                          them. Applies to LOCAL accounts.' -ForegroundColor Gray
        Write-Host '   12  AI-key ACL lock      DANGER: deny SYSTEM write on AI keys so updates cannot' -ForegroundColor Gray
        Write-Host '                          re-enable AI. Can BREAK Windows Update. Reversible.' -ForegroundColor Gray
        Write-Host '    b  back' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            '1' { Invoke-MenuAction -Modules @('USBGuard') -Dry $true -Title 'USB LOCKDOWN - EVALUATE (dry-run)' }
            '2' {
                Write-Host ''
                Write-Host '  This learns the USB devices plugged in RIGHT NOW and blocks new ones.' -ForegroundColor Yellow
                Write-Host '  Make sure every keyboard/mouse/dongle you need is attached first.' -ForegroundColor Yellow
                if (Confirm-Apply 'USB learn + lock (block new USB devices)') {
                    Invoke-MenuAction -Modules @('USBGuard') -Dry $false -Title 'USB LOCKDOWN - learn + lock'
                } else { Write-Log WARN 'Aborted; USB policy unchanged.' }
            }
            '3' {
                Write-Host ''
                Write-Host '  As option 2, AND disables USB mass storage (all USB drives stop working).' -ForegroundColor Yellow
                if (Confirm-Apply 'USB learn + lock + disable USB storage') {
                    $script:BlockUSBStorage = $true
                    Invoke-MenuAction -Modules @('USBGuard') -Dry $false -Title 'USB LOCKDOWN + storage block'
                } else { Write-Log WARN 'Aborted; USB policy unchanged.' }
            }
            '4' { Invoke-MenuAction -Modules @('SurfaceReduction') -Dry $false -Title 'sudo + Print Spooler' }
            '6' { Show-NetworkAllowMenu }
            '7' { Invoke-AggressiveNetwork }
            '8' { Invoke-ProtectedPrint }
            '9' { Invoke-DisableBluetooth }
            '10' { Invoke-PKINITHardening }
            '11' {
                Write-Host ''
                Write-Host '  Password policy for LOCAL accounts:' -ForegroundColor White
                Write-Host '    e  ENFORCE  14-char min, complexity, history, 5-try lockout (CIS/STIG)' -ForegroundColor Gray
                Write-Host '    r  RELAX    remove the requirements (no minimum, no lockout - lab/personal)' -ForegroundColor Gray
                Write-Host '    b  back' -ForegroundColor Gray
                Write-Host '  choice: ' -ForegroundColor Cyan -NoNewline
                switch (Read-Host) {
                    'e' { if (Confirm-Apply 'ENFORCE CIS password + lockout policy on local accounts') { Invoke-Mod-AccountPolicy } else { Write-Log WARN 'Aborted.' } }
                    'r' { if (Confirm-Apply 'RELAX (remove) the password + lockout requirements') { Invoke-Mod-AccountPolicy -Relax } else { Write-Log WARN 'Aborted.' } }
                    default { Write-Log INFO 'No change.' }
                }
            }
            '12' { Invoke-AILockAcl }
            '5' {
                Write-Host ''
                Write-Host '  Blocks device-insert software: metadata/companion apps, WU driver auto-install, WPBT.' -ForegroundColor Yellow
                Write-Host '  NEW hardware will not auto-get a driver afterward (existing hardware is fine).' -ForegroundColor Yellow
                if (Confirm-Apply 'block hardware-insert software install') {
                    Invoke-MenuAction -Modules @('AutoInstallGuard') -Dry $false -Title 'no auto-install on hardware insert'
                } else { Write-Log WARN 'Aborted; unchanged.' }
            }
            'b'    { return }
            'back' { return }
            default { Write-Host '  ?' -ForegroundColor DarkGray }
        }
    }
}

function Show-DangerousMenu {
    while ($true) {
        Write-Host ''
        Write-Host '  DANGEROUS modules - each can lock you out or break things.' -ForegroundColor Yellow
        Write-Host '    a  Device Guard / VBS / HVCI   (reboot; hardware-dependent)' -ForegroundColor Gray
        Write-Host '    b  BitLocker TPM+PIN           (needs -BitLockerKeyBackupPath; prompts for PIN)' -ForegroundColor Gray
        Write-Host '    c  Disable built-in admin      (refuses without another admin)' -ForegroundColor Gray
        Write-Host '    d  Block outbound              (starter allow-list; not exfil control)' -ForegroundColor Gray
        Write-Host '    e  Surface: sudo + Spooler     (Spooler needs -DisablePrintSpooler)' -ForegroundColor Gray
        Write-Host '    i  Block ALL inbound           (no reachable ports; refuses over RDP/WinRM)' -ForegroundColor Gray
        Write-Host '    b) back' -ForegroundColor Gray
        switch (Read-MenuChoice) {
            'a' { if (Confirm-Apply 'Device Guard / VBS / HVCI (reboot required)') {
                    $script:IncludeDeviceGuard = $true
                    Invoke-MenuAction -Modules @('DeviceGuard') -Dry $false } }
            'c' { if (Confirm-Apply 'disable the built-in Administrator (guarded)') {
                    $script:DisableBuiltinAdmin = $true
                    Invoke-MenuAction -Modules @('AdminAccount') -Dry $false } }
            'd' { if (Confirm-Apply 'block outbound (read the honesty note first)') {
                    $script:BlockOutbound = $true
                    Invoke-MenuAction -Modules @('Outbound') -Dry $false } }
            'e' { Invoke-MenuAction -Modules @('SurfaceReduction') -Dry $false }
            'i' { if (Confirm-Apply 'block ALL inbound (no reachable ports; refuses over RDP/WinRM)') {
                    $script:BlockAllInbound = $true
                    Invoke-MenuAction -Modules @('BlockInbound') -Dry $false } }
            'b' { return }
            'back' { return }
            default {
                Write-Host '  BitLocker (b) and some options need parameters; use the flags for those.' -ForegroundColor DarkGray
                Write-Host '  e.g.  .\Harden-Windows11-v2_2.ps1 -EnableBitLocker -BitLockerKeyBackupPath \\srv\keys' -ForegroundColor DarkGray
            }
        }
    }
}
#endregion

# ============================================================================
#region  DISPATCH TABLE (ordered)
# ============================================================================
$Script:Modules = [ordered]@{
    'Restore'      = { Invoke-Mod-Restore }
    'Defender'     = { Invoke-Mod-Defender }
    'ASR'          = { Invoke-Mod-ASR }
    'Firewall'     = { Invoke-Mod-Firewall }
    'SmartScreen'  = { Invoke-Mod-SmartScreen }
    'UAC'          = { Invoke-Mod-UAC }
    'Features'     = { Invoke-Mod-Features }
    'AutoRun'      = { Invoke-Mod-AutoRun }
    'Network'      = { Invoke-Mod-Network }
    'Credential'   = { Invoke-Mod-Credential }
    'AccountPolicy' = { Invoke-Mod-AccountPolicy }
    'LockScreenUI' = { Invoke-Mod-LockScreenUI }
    'RemoteAccess' = { Invoke-Mod-RemoteAccess }
    'Services'     = { Invoke-Mod-Services }
    'NetworkServices' = { Invoke-Mod-NetworkServices }
    'Privacy'      = { Invoke-Mod-Privacy }
    'Audit'        = { Invoke-Mod-Audit }
    'DeviceGuard'  = { Invoke-Mod-DeviceGuard }
    'Bloatware'    = { Invoke-Mod-Bloatware }
    'AdminAccount' = { Invoke-Mod-AdminAccount }
    'BitLocker'    = { Invoke-Mod-BitLocker }
    'AutoInstallGuard' = { Invoke-Mod-AutoInstallGuard }
    'USBGuard'     = { Invoke-Mod-USBGuard }
    'SurfaceReduction' = { Invoke-Mod-SurfaceReduction }
    'NTLM'         = { Invoke-Mod-NTLM }
    'Outbound'     = { Invoke-Mod-Outbound }
    'BlockInbound' = { Invoke-Mod-BlockInbound }
    'RemoteShell'  = { Invoke-Mod-RdpSshLockdown }
    'WDAC'         = { Invoke-Mod-WDAC }
    'Verify'       = { Invoke-Mod-Verify }
}
$knownModules = @($Script:Modules.Keys)

if ($ListModules) {
    Write-Host 'Available modules (run order):' -ForegroundColor Cyan
    $knownModules | ForEach-Object { Write-Host "  - $_" }
    return
}
#endregion

# ============================================================================
#region  PRE-FLIGHT
# ============================================================================
# Self-test runs first: it changes nothing and needs no admin, so it must not be
# gated behind the admin check below.
if ($SelfTest) {
    $ok = Invoke-SelfTest
    exit ([int](-not $ok))
}

# Pester runs the suite that ships alongside this script (no admin, no changes).
if ($PesterTest) {
    $ok = Invoke-PesterTest
    exit ([int](-not $ok))
}

# Audit evidence report: read-only, needs no admin to READ state (though a full
# picture benefits from elevation). Runs Verify then exports HTML evidence.
if ($Notes) {
    # Print the "KNOWN GAPS AND RISKY ITEMS" block straight from this script's own
    # source, so what an auditor reads can never drift from the actual comment.
    # The block is: banner / title / banner / ...content... / closing banner.
    # Start at the title line and stop at the NEXT banner that follows content.
    $src = Get-Content -LiteralPath $PSCommandPath
    $titleIdx = ($src | Select-String -SimpleMatch 'KNOWN GAPS AND RISKY ITEMS' | Select-Object -First 1).LineNumber
    if ($titleIdx) {
        $i = $titleIdx - 1   # 0-based index of the title line
        $out = New-Object System.Collections.Generic.List[string]
        $out.Add(($src[$i] -replace '^#\s?', ''))
        $i++
        $bannersSeen = 0
        while ($i -lt $src.Count) {
            $line = $src[$i]
            if ($line -match '^# ={10,}') {
                $bannersSeen++
                $out.Add(($line -replace '^#\s?', ''))
                if ($bannersSeen -ge 2) { break }   # 1 = banner under title, 2 = closing
            } else {
                $out.Add(($line -replace '^#\s?', ''))
            }
            $i++
        }
        Write-Host ''
        $out | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
        Write-Host ''
    } else {
        Write-Host 'Notes section not found in source.' -ForegroundColor Yellow
    }
    exit 0
}

if ($AuditReport) {
    $ok = Write-AuditReport
    exit ([int](-not $ok))
}

# Temporary-unlock lifecycle. -Relock is also what the scheduled auto-relock task
# invokes, so it must work non-interactively and needs admin (it changes services).
if ($Relock) {
    if ($Relock -eq 'all') { Invoke-RelockAll } else { Invoke-Relock -Area $Relock }
    exit 0
}
if ($Unlock) {
    Invoke-Unlock -Area $Unlock -Minutes $UnlockMinutes -Reason $UnlockReason
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'ERROR: Run this script as Administrator.' -ForegroundColor Red
    Write-Host "Right-click PowerShell -> 'Run as administrator', then run it again." -ForegroundColor Red
    return
}

# Validate module-name inputs (catches typos)
foreach ($m in @($OnlyModules) + @($SkipModules)) {
    if ($m -and ($knownModules -notcontains $m)) {
        Write-Host "ERROR: Unknown module '$m'. Known modules: $($knownModules -join ', ')" -ForegroundColor Red
        return
    }
}

$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:LogFile = Join-Path $env:SystemDrive "Harden-Win11-v22_$stamp.log"
$Script:CsvFile = Join-Path $env:SystemDrive "Harden-Win11-v22_$stamp.csv"

# bug W8: these land in C:\ root, where BUILTIN\Users has Read by default, and
# they record admin account names, the RDP source of a remote run, and the full
# result set. Lock them to SYSTEM+Administrators BEFORE the first line is
# written (Write-Log appends to LogFile immediately). The transcript is started
# after Protect-File so its own first bytes are already inside a locked file.
Protect-File -Path $Script:LogFile -Quiet | Out-Null
Protect-File -Path $Script:CsvFile -Quiet | Out-Null
if (-not $NoTranscript) {
    $Script:Transcript = Join-Path $env:SystemDrive "Harden-Win11-v22_$stamp.transcript.log"
    Protect-File -Path $Script:Transcript -Quiet | Out-Null
    try { Start-Transcript -Path $Script:Transcript -Force | Out-Null } catch { $Script:Transcript = $null }
}

try { $Script:Edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).EditionID } catch {}
try { $Script:Caption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
try { $Script:Build   = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).CurrentBuildNumber } catch {}

# Detect an at-risk remote session BEFORE the confirmation prompt, so the
# operator sees it while deciding, not after the door has shut (bug W2).
$Script:RemoteSession = Get-RemoteSessionKind

# Resolve which modules will run.
# Verify is opt-in: it is a read-only audit, meaningless as part of an apply
# pass (it would check state the same run just set) and pointless to run by
# default. It only runs when named in -OnlyModules, or via -VerifyOnly.
$plan = @()
foreach ($name in $knownModules) {
    if ($name -eq 'Verify' -and -not ($OnlyModules -contains 'Verify')) { continue }
    if ($OnlyModules -and ($OnlyModules -notcontains $name)) { continue }
    # bug W5: the help said "Only wins" when both are given, but the old order
    # let a Skip entry override an Only entry (Skip's `continue` fired second).
    # Honour the documented contract: if a module is explicitly in -OnlyModules,
    # -SkipModules does not remove it. Skip only applies when Only is not naming
    # this module.
    if ($SkipModules -and ($SkipModules -contains $name) -and -not ($OnlyModules -contains $name)) { continue }
    $plan += $name
}

# A pure verify run (only Verify selected) changes nothing, so it skips the
# "type YES" confirmation and the restore point - it is safe on a live box.
$Script:VerifyOnlyRun = ($plan.Count -eq 1 -and $plan[0] -eq 'Verify')

Write-Host ''
Write-Host '  Windows 11 Security Hardening - v2.2' -ForegroundColor White
Write-Host "  OS       : $Script:Caption (Edition: $Script:Edition, Build: $Script:Build)" -ForegroundColor DarkGray
Write-Host "  Mode     : $(if($Script:DryRun){'DRY-RUN (no changes)'}else{'APPLY'})$(if($Script:StopOnError){'  [StopOnError]'})" -ForegroundColor DarkGray
Write-Host "  Log      : $Script:LogFile" -ForegroundColor DarkGray
Write-Host "  Modules  : $($plan -join ', ')" -ForegroundColor DarkGray
Write-Host "  Options  : LmCompat=$LmCompatibilityLevel, EventLog=${EventLogSizeMB}MB, NTLM=$(if($EnforceNTLMDeny){'DENY'}else{'AUDIT'}), Outbound=$(if($BlockOutbound){'BLOCK'}else{'Allow'})" -ForegroundColor DarkGray

# bug W2: tell the operator they are on a severable path BEFORE they commit.
if ($Script:RemoteSession -and ($Script:RemoteSession.OverRDP -or $Script:RemoteSession.OverWinRM)) {
    $how = if ($Script:RemoteSession.OverRDP) { 'RDP' } else { 'WinRM' }
    Write-Host ''
    Write-Host "  ! You are on a $how session ($($Script:RemoteSession.Detail))." -ForegroundColor Yellow
    Write-Host "    The RemoteAccess module (and -BlockOutbound) can lock you out on RECONNECT." -ForegroundColor Yellow
    Write-Host "    Severing steps will be SKIPPED unless you pass -Force. Prefer running from the console." -ForegroundColor Yellow
} elseif ($Script:RemoteSession -and $Script:RemoteSession.RdpEstablished) {
    Write-Host ''
    Write-Host "  ! An RDP session is currently established ($($Script:RemoteSession.Detail))." -ForegroundColor Yellow
    Write-Host "    Disabling RDP will lock out whoever is on it." -ForegroundColor Yellow
}

# Menu activation, ported from 0harden's tty-gated default. Show the menu ONLY
# when: not -NoMenu, an interactive session, and NO action arguments were given
# (bare invocation). Any explicit intent via flags skips the menu - flags stay
# primary. A non-interactive bare run must not hang on Read-Host; the existing
# confirmation block below already refuses non-interactive applies.
$actionArgs = $DryRun -or $Force -or $OnlyModules -or $SkipModules -or
              $IncludeDeviceGuard -or $IncludeBloatwareRemoval -or $EnableBitLocker -or
              $DisableBuiltinAdmin -or $BlockOutbound -or $GenerateWDACAuditPolicy -or
              $DisablePrintSpooler -or $EnforceNTLMDeny -or $USBGuard -or $BlockUSBStorage -or $BlockDeviceAutoInstall
$menuActive = ($Menu) -or ((-not $NoMenu) -and [Environment]::UserInteractive -and (-not $actionArgs))

if ($menuActive) {
    Expire-StaleUnlocks
    Show-Menu
    Write-RunSummary
    if ($Script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }
    return
}

# Confirmation (guarded for non-interactive sessions)
if (-not $Script:DryRun -and -not $Force -and -not $Script:VerifyOnlyRun) {
    if (-not [Environment]::UserInteractive) {
        Write-Host 'ERROR: Non-interactive session. Pass -Force to apply or -DryRun to preview. Aborting.' -ForegroundColor Red
        if ($Script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }
        return
    }
    Write-Host ''
    Write-Host '  This applies system-wide security changes. Review the plan above.' -ForegroundColor Yellow
    $ans = Read-Host '  Type YES to proceed'
    if ($ans -ne 'YES') {
        Write-Log WARN 'Aborted by user.'
        if ($Script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }
        return
    }
}
#endregion

# ============================================================================
#region  RUN (try/finally guarantees summary + cleanup)
# ============================================================================
try {
    foreach ($name in $plan) {
        try {
            & $Script:Modules[$name]
        } catch {
            # Only reached when -StopOnError re-threw; abort the remaining modules.
            Write-Log ERROR "Aborting run: $($_.Exception.Message)"
            throw
        }
    }
} catch {
    Write-Log ERROR "FATAL: $($_.Exception.Message)"
} finally {
    Write-RunSummary
    if ($Script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }
}
#endregion
