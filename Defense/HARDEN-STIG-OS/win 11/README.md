# Harden-Windows11 v2.2

A modular, gated, **reversible** Windows 11 hardening script for Pro/Enterprise,
built the same way as its Linux sibling: every behaviour change is guarded, every
apply is dry-runnable and produces an undo script, and the decision logic is
covered by an automated test harness.

> **First rule:** run `-SelfTest`, then `-DryRun` on a snapshot, before you ever
> apply. Nothing here should touch a machine you care about until you have seen
> the preview.

---

## What's in the bundle

| file | what it is |
|---|---|
| `Harden-Windows11-v2_2.ps1` | the hardening script (run this) |
| `run-tests.bat` | double-click to run all tests (native + Python + Pester) |
| `0wintest-logic.py` | the verified decision-logic harness (needs Python) |
| `Harden-Windows11.Tests.ps1` | Pester suite for cmdlet-level tests (needs a Windows box) |
| `0harden-windows-notes.md` | full engineering changelog (every fix, why, and how tested) |
| `README.md` | this file |

You only *need* the `.ps1`. The rest is testing and documentation.

---

## First run (do this in order)

```powershell
# 1. Prove the logic is sound. No admin, no changes, safe anywhere.
.\Harden-Windows11-v2_2.ps1 -SelfTest

# 2. Preview everything on a SNAPSHOT/VM. Shows every action as "WOULD ...".
.\Harden-Windows11-v2_2.ps1 -DryRun

# 3. Read what it would do. Then apply the safe baseline (asks you to confirm).
.\Harden-Windows11-v2_2.ps1            # bare = interactive menu (recommended)

# 4. Afterward, confirm it actually took. Read-only, safe on a live box.
.\Harden-Windows11-v2_2.ps1 -OnlyModules Verify
```

Run **as Administrator** for anything except `-SelfTest`.

---

## The menu

Running the script bare on an interactive session opens a menu:

```
1  evaluate       dry-run the safe baseline. Changes nothing.
2  harden         apply the safe baseline (asks to confirm).
3  check for gaps  audit what is actually true now. Read-only.
                  Offers to write an HTML audit-evidence report.
4  dangerous       BitLocker, Device Guard, disable admin, block outbound.
5  extra security  USB lockdown, sudo/spooler, aggressive network, protected
                  print (WPP), disable Bluetooth, PKINIT SHA-1, password policy,
                  AI-key ACL lock (danger: can block updates - see below).
6  run self-tests  verify this script is sound. Changes nothing.
7  help            the full command reference.
8  operational     temporarily unlock an area (captive portal / print / SMB /
                  RDP / WinRM), adopt a USB device, or re-lock. Self-reverting.
9  level 2         lockout-risk lockdowns (RDP+SSH, block all inbound, block
                  outbound, NTLM deny). Run one individually or batch all four.
                  Kept out of the safe baseline; each confirms and guards your
                  current remote session.
q  quit
```

The menu is only a front end - every action is also a flag, and flags stay
primary (any flag you pass skips the menu). A scheduled task or CI run never
sees the menu and never hangs waiting for input.

Two documentation flags worth knowing: `-Notes` prints the "known gaps and risky
items" section (what the tool does NOT do, and which changes carry risk) straight
from the source. `-AuditReport` runs a read-only verify and writes a self-contained
HTML control-mapping report next to the script - an audit deliverable.

---

## Safety guarantees - and their honest limits

This script tries hard not to lock you out or lie to you. What that means:

- **Remote-access lockout guard.** If you run it over RDP or WinRM, the steps
  that disable remote access are *skipped* unless you pass `-Force`. Your current
  session survives; the danger it prevents is the next reconnect.
- **USB learn+lock never blocks input.** Keyboard/mouse are force-allowed, and it
  refuses to apply a deny-all policy if it learned zero devices. It uses an
  allowlist, never a class block.
- **Egress honesty.** `-BlockOutbound` is *not* exfil control and the script says
  so - it stops odd-port malware and logs new egress, but anything speaking HTTPS
  to a host of its choosing still gets out. DoH is pinned to known resolvers.
- **Verify never lies.** The audit reports `PASS` / `FAIL` / `PENDING` /
  `INCONCLUSIVE` - and "I couldn't check" (`INCONCLUSIVE`) is never reported as a
  pass.
- **Secrets are locked down.** The run log, CSV, transcript, and the BitLocker
  recovery-key file are written with SYSTEM+Administrators-only ACLs, *before*
  any secret lands in them.
- **One deliberately sharp exception: the AI-key ACL lock (extra security 12).**
  Every other change is reversible without side effects. This one is reversible
  too (it records an undo and prints a restore command), but it *deliberately*
  denies SYSTEM write on the AI-policy keys so Windows Update cannot re-enable AI -
  which can make updates fail on those keys. It is gated behind a typed phrase and
  a full-screen warning, off by default, and the read-only audit reports when it is
  active. Most people should instead just re-run this tool after big updates.

**What is proven, and what is not:** the safe baseline has been run on real
hardware (apply, read-only audit, and self-test all clean), and two hardware-only
bugs were found and fixed that way. The decision logic is harness-verified. The one
piece still unproven on a box is the operational auto-relock timer actually firing;
treat that path as untested until you have watched it self-revert. Watch the
`-DryRun` output before applying anything sharp - especially USB lockdown, where
menu **6  1 (evaluate)** shows exactly what it would learn before you commit.

---

## Rollback

Every `apply` writes `C:\Harden-Win11-UNDO_<timestamp>.ps1`. It:

- reverses the registry / service / firewall changes it made, in reverse order,
- lists everything that was **skipped** (so you know what was *not* changed),
- has a **MANUAL** section for what a script cannot safely reverse (BitLocker
  decryption, removed apps, removed features) - listed with instructions, never
  silently dropped.

To roll back: review that file, then run it as Administrator (it asks to confirm).

---

## Testing

```powershell
.\Harden-Windows11-v2_2.ps1 -SelfTest      # logic + static audit; no deps, no admin
.\Harden-Windows11-v2_2.ps1 -PesterTest    # runs the Pester suite next to the script
run-tests.bat                               # convenience: runs both of the above
```

The test files ship alongside the script - keep them in the same folder.

- `-SelfTest` - decision-logic truth tables + a static audit of the script's own
  source (coherence, no stale version, parser-hazard scan, ASCII-only). This is
  the one that matters and it needs nothing installed.
- `-PesterTest` - runs Harden-Windows11.Tests.ps1 (which sits next to the script).
  Works with Pester 3.4 (in-box) and 5.
- The Python reference harness (0wintest-logic.py, with --sabotage) runs anywhere
  Python is available - use it for development.

---

## Common invocations

```powershell
# safe baseline, non-interactive (e.g. imaging), with the confirmation skipped
.\Harden-Windows11-v2_2.ps1 -Force

# only specific areas
.\Harden-Windows11-v2_2.ps1 -OnlyModules Defender,ASR,Firewall,Audit

# skip areas, and loosen NTLM for legacy SMB devices
.\Harden-Windows11-v2_2.ps1 -SkipModules Privacy,Bloatware -LmCompatibilityLevel 3

# extreme: block new hardware from pulling drivers/apps (existing hardware is fine)
.\Harden-Windows11-v2_2.ps1 -BlockDeviceAutoInstall

# extreme: learn present USB, block new devices (run at the CONSOLE)
.\Harden-Windows11-v2_2.ps1 -USBGuard

# BitLocker with key escrow (prompts for a numeric PIN)
.\Harden-Windows11-v2_2.ps1 -EnableBitLocker -BitLockerKeyBackupPath \\server\keys

# disable the built-in admin (refuses unless another admin exists)
.\Harden-Windows11-v2_2.ps1 -DisableBuiltinAdmin -VerifiedAdminAccount AdminLcl_001

# list every module, or get full help
.\Harden-Windows11-v2_2.ps1 -ListModules
Get-Help .\Harden-Windows11-v2_2.ps1 -Detailed

# write an HTML audit-evidence report (read-only), or print the known-gaps notes
.\Harden-Windows11-v2_2.ps1 -AuditReport
.\Harden-Windows11-v2_2.ps1 -Notes

# temporarily allow printing for 30 min, auto-relocks itself; or re-lock everything now
.\Harden-Windows11-v2_2.ps1 -Unlock printing -UnlockMinutes 30 -UnlockReason 'client site'
.\Harden-Windows11-v2_2.ps1 -Relock all
```

---

## Modules (run order)

Safe baseline (applied by "harden"): Defender, ASR, Firewall, SmartScreen, UAC,
Features, AutoRun, Network, Credential, LockScreenUI, RemoteAccess, Services,
NetworkServices, Privacy, Audit, NTLM. (A System Restore point is created first,
unless `-SkipRestorePoint`.)

Opt-in / dangerous (flag or menu only): AccountPolicy (password/lockout, with an
enforce and a relax/remove path), DeviceGuard, Bloatware, AdminAccount, BitLocker,
Outbound, BlockInbound (disable every inbound allow rule - no reachable ports),
RemoteShell (RDP+SSH lockdown), WDAC, SurfaceReduction, USBGuard, AutoInstallGuard.

Read-only: Verify.

---

## Provided as-is

Test on a snapshot first. For fleets, prefer Microsoft Security Baselines /
Intune / GPO / CIS Benchmarks as the source of truth; this script is a fast,
reversible baseline for individual boxes. The .ps1 is self-contained for hardening (no runtime dependencies); the test files ship alongside it.
