# Harden-Windows11 v2.2 — port of 0harden's lessons

Companion to the Linux `0harden.sh` work. Same method: bugs found by reading
get fixed with a guard AND a test; bugs only real hardware can show are flagged,
not guessed at.

## HANDOVER - START HERE (current state as of 39th pass)

**What this is:** a Windows 11 hardening script (PowerShell 5.1, single-file, zero-
dependency) that ports the design discipline of the Linux 0harden.sh. Built for
Brandon, pentester at AINetGuard, box "TheKraken" (Win11 Home, Core, Build 22631,
files at `D:\code\web_0ui\build_0harden\win 11\`). Preferences: terse output,
ASCII-only (NO em dashes), no filler, technical peer, single-file philosophy.

**Current state:** 4538 lines, 75 functions, 28 modules, 41/41 params documented,
35 verify checks, 39 harness sabotages. Balanced, ASCII, no double-backslash, ALL
PASS. Proven on real hardware for apply + verify + self-test + the two box-found
bug fixes (Protect-Directory -Quiet, duplicate ASR GUID).

**The 6 deliverable files (in outputs):**
- `Harden-Windows11-v2_2.ps1` - the script (the only file the user runs on the box)
- `run-tests.bat` - test launcher
- `0wintest-logic.py`, `Harden-Windows11.Tests.ps1` - the harnesses
- `README.md` - user-facing (rewritten 38th pass to match reality)
- `security-controls-taxonomy.json` + `.md` - control coverage map (39th pass)

**Working files (in /home/claude):** `win.ps1` is the working copy - EDIT THIS, then
`cp win.ps1 Harden-Windows11-v2_2.ps1` (harness reads that name). Notes: this file.

**MANDATORY after every edit (the verification discipline):** here-string-aware
brace/paren/square balance (all 0), non-ASCII scan (0), double-backslash scan on HK
paths (0 - recurring self-inflicted bug from Python heredocs; use raw-string
r'''...''' heredocs), PS7-syntax scan (no ternary/??/?.//&&/|| - box is 5.1), then
`python3 0wintest-logic.py --sabotage` (all catch, clean green). When an EMBEDDED
tool file changes (py/bat/Tests/README), re-embed its base64 into win.ps1 (drift
check enforces it). The .py embeds the other 3; the ps1 embeds all 4.

**THE ONE UNVERIFIED PIECE (highest-value remaining box test):** whether the
schtasks auto-relock actually FIRES. Test: `-Unlock printing -UnlockMinutes 2`,
watch it self-relock, confirm menu 8 countdown + menu 3 says re-locked. Everything
else statically/harness-verifiable IS verified.

**Standing caveats to keep giving the user:** (1) CIS/STIG control NUMBERS are
indicative - have the compliance owner cross-check the exact benchmark version.
(2) Some 24H2/25H2 items (Recall keys, PKINIT) are near/past knowledge cutoff -
worth confirming on the real build.

**If asked to "keep on it":** the disciplined move is usually to RESIST padding.
The tool is mature; recent guide reviews increasingly CONFIRM coverage rather than
reveal gaps (37th pass was a correct no-op). Real value left: (a) the box-only
schtasks test, or (b) a genuinely NEW guide - but recognize re-submitted ones.

---

## Files

- `Harden-Windows11-v2_2.ps1` — the hardened script (was v2.1)
- `0wintest-logic.py` — decision-logic harness. **Verified** (runs + sabotage-checked here). Tests branching, not PowerShell.
- `Harden-Windows11.Tests.ps1` — Pester suite. **UNVERIFIED** until run on a Windows box. Tests semantics. Read its header first.
- this file

## What changed from v2.1 (the review pass)

**W1 — egress honesty (`-BlockOutbound`).** v2.1 allowed 443/53 to *anywhere*
and all browsers to anywhere, then framed it as egress control. Same bug 0harden
shipped and had caught in review. Fixed: DoH is pinned to known resolvers
(edit the list per environment); the run states plainly that an L4 port
allowlist stops odd-port malware but is NOT exfil control; browser-anywhere is
kept (a workstation must browse) but labeled as the widest hole. Self-heals a
v2.1 wide DoH rule by rebuilding it pinned — caught mid-fix that the idempotency
guard would otherwise leave the old wide rule in place (bug 16 family).

**W2 — lockout guard (RDP/WinRM).** v2.1's RemoteAccess module disabled RDP by
default; run over RDP, that locks you out on the next reconnect. Bug 44 ported.
`Get-RemoteSessionKind` detects RDP (SESSIONNAME), WinRM (parent-process walk
for wsmprovhost — SESSIONNAME misses WinRM), and any live RDP session.
`Assert-NotSeveringOurAccess` refuses the sever in APPLY mode on a remote
session unless `-Force`, and the banner warns before the confirmation prompt.

**W3 — verify module.** New `-OnlyModules Verify`: read-only audit, no confirm,
no restore point. Three-state verdicts (PASS/FAIL/PENDING/INCONCLUSIVE/INFO)
with the bug-36 rule baked in: a check that cannot run its tool says
INCONCLUSIVE, never PASS. Handles third-party AV (INCONCLUSIVE, not FAIL),
reboot-gated settings like RunAsPPL (PENDING, not PASS), and catches the W1
drift automatically.

**W4 — the harnesses.**

**W5 — `-OnlyModules`+`-SkipModules` doc lie.** Help said "Only wins"; the code
let Skip override Only (Skip's `continue` fired second). A module in both was
skipped, not run. Bug 26 family (doc asserts behavior the code lacks). Fixed so
Only wins as documented; modeled + sabotage-tested in the logic harness.

**W6 — Features false-fail on absent features.** `Disable-WindowsOptionalFeature`
throws on an already-absent feature, and SMB1Protocol ships removed on current
Win11 builds - so the run logged `[Failed]` and flagged a reboot for a no-op.
Bug 42 family (installed != present). Now checks state first: absent/disabled =
already done. Verify also gained an SMBv1 check to close the loop.

**W7 — BitLocker PIN note.** Length check is correct but numeric-only PINs are
the default; a length-valid alpha PIN passes validation then fails at
Add-BitLockerKeyProtector without the enhanced-PIN policy. Added a ManualStep;
no code change (enhanced PINs are legitimate).

**W8 — world-readable run artifacts.** The log/CSV/transcript land in C:\ root
where BUILTIN\Users has Read, and they record admin account names and the RDP
source of a remote run. Bug 39 family. Now locked to SYSTEM+Administrators at
creation, before the first line is written. Verify checks the log ACL.

**W9 — plaintext BitLocker recovery key, world-readable (SEVERE).** The escrow
file holds the plaintext recovery password. Written with Out-File it inherits
the parent ACL; a local backup dir inherits C:\ so any standard user could read
the key and decrypt a stolen/imaged disk - the escrow step defeating the control
it protects. Now the directory (if local) and the file are locked to
SYSTEM+Administrators BEFORE the key is written. The ordering is the bug (bug 39:
restrict before write, not after), so it is modeled as a sequence invariant in
the harness (MODEL 5) and sabotage-tested.

**W10 — dry-run hid a destructive op (self-inflicted).** My own W1 self-heal put
the scope check AND the Remove-NetFirewallRule INSIDE an Invoke-Step scriptblock.
Invoke-Step returns before running its block on -DryRun, so the preview showed
"WOULD: Outbound allow rule (pinned)" but was blind to the fact it DELETES the
old wide rule first. Bug 31 exactly - dry run hiding a real command - introduced
two passes earlier. Fixed: detection is now outside Invoke-Step (read-only, safe
on dry-run) and the rebuild is its own step whose LABEL discloses the deletion.
The harness gained MODEL 6, a static source scan that flags any undisclosed
destructive step, sabotage-tested.

**W11 — DANGEROUS module under-described on dry-run.** BitLocker's dry-run showed
the reg policies (via Set-Reg) but was silent on the enable + plaintext-key
escrow + ACL lock. Not destructive-hidden like W10, but a preview of a
full-disk-encryption module must say what it will do. Added the WOULD narration.

Fourth review pass used promise-testing (does dry-run preview everything apply
does? - the method that found bug 31 on Linux), applied hardest to my OWN
additions since the self-inflicted rate runs ~1 in 6. It found exactly one
self-inflicted bug (W10), on schedule.

Third review pass used the attack-the-artifacts method (bug 39 family). Second
pass used argument/value fuzzing (the method that found bugs 26/27/
42 on Linux) rather than re-reading for the same families. Also confirmed the
Privacy edition-gate is correctly built (bug 29/30 lesson already applied by the
original author) - noted so it is not "fixed" into a regression.

## What is VERIFIED vs what needs the box

Verified here (Python runs, sabotage-checked):
- the lockout guard decision table (all 6 cases)
- wide-vs-pinned classification + self-heal (CREATE/REBUILD/SKIP)
- the three-state verify verdicts incl. third-party AV and reboot-pending
- plan resolution + Verify opt-in

The sabotage loop caught a real hole in my own test (a PENDING sabotage hook
placed after the return it meant to intercept — dead code, test asleep). Fixed.

NOT verified — needs a real Windows box (the `sshd -T` equivalent gap):
1. `SESSIONNAME` / `wsmprovhost` detection on a real RDP and a real WinRM session.
2. `Get-MpComputerStatus.AMRunning` when Defender is active-but-passive.
3. `Get-NetFirewallAddressFilter.RemoteAddress` actual shape for "is this wide".
4. The Pester suite has never run. Follow its first-run protocol, and
   sabotage-verify each Context (break a guard, confirm the test goes red)
   before trusting a green run.

## First five minutes on the box

```powershell
# 1. static + logic (safe anywhere)
python .\0wintest-logic.py --sabotage        # must end all-green, all sabotages caught
Install-Module Pester -Force -SkipPublisherCheck
Invoke-Pester .\Harden-Windows11.Tests.ps1   # expect SOME red; fix mocks per header

# 2. preview on a snapshot
.\Harden-Windows11-v2_2.ps1 -DryRun

# 3. the audit (read-only, safe on a live box)
.\Harden-Windows11-v2_2.ps1 -OnlyModules Verify
```

Then sabotage-verify the Pester Contexts, then run the mutating modules on a
snapshot in the same risk order the Linux VM plan uses (least-likely-to-lock-you-
out first; RemoteAccess and Outbound last).

## Not done / deferred

- BitLocker, DeviceGuard, WDAC modules unchanged from v2.1 (already well-gated).
- No menu yet (the Linux one earned its keep; the Windows equivalent is a
  reasonable next step but wasn't asked for).
- The Pester Integration tag (dry-run-makes-no-changes) is a placeholder;
  building the mutator mocks is the highest-value box-side work after detection.


## Guide review + coverage-diff (fifth pass)

A third-party "Win11 25H2 Aggressive Hardening" guide was reviewed. Findings:

WRONG in the guide (do not copy):
- R1 (fatal): nearly every block uses `Set-ItemProperty -PropertyType` - that
  parameter does not exist on Set-ItemProperty (it is New-ItemProperty). As
  written, the guide's entire script body throws. Generated-and-never-run, same
  fingerprint as the Linux guides.
- R4 (dangerous): `Disable-LocalUser -Name "Administrator"` - hardcoded name
  (fails on a renamed built-in) with NO alternate-admin check. The ps1's
  AdminAccount module guards exactly this lockout; the guide reintroduces it.
- R6: auditpol by English subcategory NAME (fails on non-English Windows). The
  ps1 uses locale-independent GUIDs.
- R3: Spooler stop with no gate. R5: SMB signing mislabeled as encryption,
  client-only. R7: VBS RequirePlatformSecurityFeatures=1 (ps1 uses 3, +DMA).
- R2: telemetry=0 with no Pro/Home floor warning (ps1 already warns).

ADOPTED from the guide (real gaps it correctly identified):
- ASR BYOVD rule 56a863a9 (block exploited vulnerable signed drivers) - the
  guide's single best addition; blocks a common EDR-blinding kill-chain.
- SMB signing on BOTH client and server (guide did client only, mislabeled).
- ROCA WHfB validation (SamNGCKeyROCAValidation=2) - safe on unaffected TPMs.
- Activity History + Widgets-on-lock-screen off (Privacy).
- New SurfaceReduction module for Windows sudo + Print Spooler - but GATED the
  way the guide was not: sudo only if present; Spooler only on -DisablePrintSpooler
  and never when shared printers exist without -Force (bug 41 lesson). Modeled
  as MODEL 7, sabotage-tested.

NOT adopted (context-dependent, would break a standalone box if defaulted):
- WSUS/DODownloadMode (hardcoded internal server URL breaks updates off-domain).
- RemoveWindowsStore / AppInstaller lockdown (breaks winget; enterprise choice).
These belong behind explicit switches with a domain check, not in a baseline.

Fifth method: coverage-diff against an external baseline (what is MISSING vs what
is WRONG) - the method that found the "no time sync at all" gap on Linux.

## Interactive menu (sixth pass) + a refactor bug it surfaced

Built the guided menu (the remaining piece of the original "menu + verify" ask).
PowerShell calls modules IN-PROCESS, so the bash version's shell-out/double-prompt
bug class does not exist here. Activation ported from 0harden's tty gate: menu is
the default only when interactive, not -NoMenu, and no action args; any flag skips
it (flags stay primary); non-interactive never hangs. Modeled as MODEL 8 with two
sabotages (menu_ignores_tty, state_leak).

The state-hygiene guard is the load-bearing part: each menu action sets $Script:DryRun
EXPLICITLY at entry, so a dry-run "assess" cannot leak into a later "harden" and
silently no-op. MODEL 8's state_leak sabotage proves that test bites.

REFACTOR BUG found and fixed (self-inflicted, ~1 in 6 as always): extracting the
menu meant the menu path returned BEFORE the try/finally summary, so a menu 'harden'
ran the modules but printed no summary/CSV/reboot-list. Fixed by extracting
Write-RunSummary as one source of truth called by both paths. Also caught (and
immediately fixed) a bad str_replace that renamed Protect-File's header to Write-Log
- exactly the "refactoring introduces self-inflicted bugs" family from the Linux work,
caught by viewing after the edit.

Sixth method: refactoring (found 3 bugs on Linux, 2 self-inflicted). Same ratio held.

## Rollback log / undo script (seventh pass)

On an apply, the script now emits a standalone Harden-Win11-UNDO_<stamp>.ps1 that:
- reverses the captured REGISTRY / SERVICE / FIREWALL changes in LIFO order
  (last change reverted first)
- carries a system-info header (computer, OS, edition, build, session type, source log)
- lists every SKIPPED item (not changed => nothing to undo) as comments
- has a MANUAL section for what a script cannot safely reverse (BitLocker
  decryption, removed apps, removed features) - listed, never auto-run

Design ported from 0harden's rollback (bugs 34/38): capture the prior state AT
change time, not later, and record EVERYTHING including "cannot undo" so rollback
never silently leaves state behind or claims a reversal it lacks (bug 26 honesty).
Set-Reg captures prior value+kind before writing - that covers the bulk
automatically; no-op sets are not recorded. Reversible Invoke-Step ops (services,
firewall rules, outbound-block flip, feature disable) attach an explicit undo;
irreversible ones attach a Manual note.

The undo .ps1 is admin-gated, confirm-gated (type YES, or -Force), wraps every
action in try/catch, and is written with the restrictive ACL (bug 39 - it holds
system info and is itself state-changing). Modeled as MODEL 9: LIFO ordering,
reversible-vs-manual split, and single-quote escaping of registry paths, with two
sabotages (undo_not_lifo, undo_drops_manual).

VM-test priority: Binary/MultiString value restore (almost all settings here are
DWord, so this path is rarely exercised - the one place the model cannot vouch
for the real -PropertyType typing).

Seventh feature: rollback generation. The remaining untested METHOD is
idempotency-by-double-run, which needs the box.

## Attacking my own undo feature (eighth pass)

Turned the bug-hunt on the rollback code I just wrote (self-inflicted rate ~1 in 6,
so the newest code is the likeliest to be wrong). Found four gaps, all mine:

- W-UNDO-1: the value renderer only handled [string] (quoted) vs everything-else
  (bare). A MultiString/Binary prior would interpolate to "System.Object[]" - a
  broken restore line, silently. ExpandString would re-expand %VARS% wrongly.
  Fixed: only DWord/QWord/String get a literal restore; other types go to the
  MANUAL section with the path/name so the operator restores by hand. A rollback
  that emits a broken line is worse than one that says "restore this by hand"
  (bug 26 honesty, applied to my own code). Modeled + sabotaged (undo_bad_type).
- W-UNDO-2: the Outbound self-heal REBUILD path created a pinned rule but
  recorded no undo. Fixed: it now records removing the pinned rule, plus a manual
  note that the old wide rule is deliberately NOT auto-restored (re-opening the
  hole is a decision, not an automatic step).
- W-UNDO-3: built-in Administrator disable was reversible (Enable-LocalUser) but
  recorded no undo. Added. Guest gets a manual note (re-enabling Guest is almost
  never wanted).
- W-UNDO-4: auditpol changes had no undo and no note. Added a manual note (prior
  per-subcategory state is not captured).

Re-run idempotency confirmed safe: a second harden sees prior==new for already-set
values, records nothing (no-op skip), so UNDO_2 is near-empty and UNDO_1 still
reverts to pristine. The no-op skip is what makes repeated hardening safe to undo.

Eighth pass method: attacking my own newest feature. Fifteen sabotages now, all
caught. The remaining untested METHOD across the whole Windows effort is
idempotency-by-literal-double-run, which needs the box.

## Extra-security menu + USB learning mode (ninth pass)

Restructured the menu to the requested numbered layout: 1 evaluate, 2 harden,
3 check for gaps, 4 dangerous, 5 advanced, 6 extra security. Option 6 opens a
submenu for the extreme items.

USB LEARNING MODE (Invoke-Mod-USBGuard): enumerates the USB devices present NOW,
allowlists their hardware IDs, and sets Device Installation policy to deny NEW/
unlisted devices. This is the "learn present, block new" the user asked for.

The console-brick guards (all modeled as MODEL 10, sabotage-tested):
- HID / keyboard / mouse are FORCE-INCLUDED via a dedicated second scan, so the
  console can never lose input even if a device was momentarily not 'OK'.
- If zero IDs are learned, it REFUSES (a deny-all with an empty allowlist would
  block everything, including input).
- The policy uses AllowDeviceIDs + DenyUnspecified (allowlist + deny-others) and
  deliberately NEVER sets DenyDeviceClasses for input - class-blocking keyboards
  is the classic bricking move.
- Refuses from an RDP/WinRM session without -Force (a remote operator cannot see
  the console's input devices). Reuses the W2 remote-session detection.
- Menu 6->1 is "USB: evaluate" - a dry-run that narrates the WOULD-learn list so
  you see it before committing.
- Every write is Set-Reg, so it lands in the undo script and honours -DryRun.
- -BlockUSBStorage optionally disables USBSTOR (mass storage) as a SEPARATE
  control from device-install blocking - the two are conflated in guide-style
  "one switch" USB lockdowns and they are not the same thing.

Verify gained a USB-lockdown check: if deny-unspecified is ON but the allowlist
is EMPTY, that is a FAIL (input-loss risk), not a pass.

VM-test priority (the sshd -T equivalent for this feature): Get-PnpDevice /
Get-PnpDeviceProperty output shape and whether DEVPKEY_Device_HardwareIds returns
the expected array. Run menu 6->1 (evaluate) on TheKraken and read the WOULD-learn
list BEFORE ever applying. Eighteen sabotages now, all caught.

## Device-insert software-install prevention (tenth pass)

Added Invoke-Mod-AutoInstallGuard: closes the paths by which inserting hardware
pulls software. Three mechanisms, exact registry keys verified:
- Device metadata from the internet (PreventDeviceMetadataFromNetwork=1) - stops
  the companion-app metadata fetch on insert. Low breakage, always applied.
- Windows Update driver auto-search (DriverSearching\DontSearchWindowsUpdate=1,
  DontPromptForWindowsUpdate=1, WindowsUpdate\ExcludeWUDriversInQualityUpdate=1)
  - stops a new device auto-pulling a driver. This is the medium-risk part: NEW
  hardware wont auto-get a driver afterward (existing hardware unaffected). Stated
  in a loud ManualStep, not hidden.
- WPBT (Session Manager\DisableWpbtExecution=1) - the closest sibling: firmware
  hands Windows a binary it EXECUTES at boot, a documented persistence/supply-chain
  vector. Disabling execution closes it.

Gated as extra-security (menu 6->5, or -BlockDeviceAutoInstall), NOT in the safe
baseline, because the driver-block changes new-hardware behaviour. All via Set-Reg,
so undo + dry-run come free. Verify reports these as INFO-when-absent (opt-in), not
FAIL - avoiding the bug 29/30 cry-wolf trap. Modeled as MODEL 11 with two sabotages:
wpbt_wrong (value 0 does not disable WPBT) and driver_no_note (silent new-hardware
breakage). Twenty sabotages now, all caught.

VM-test note: DisableWpbtExecution takes effect at next boot; verify it via
msinfo32 / the absence of the WPBT-launched process, not immediately.

## Coherence audit (eleventh pass)

After the script doubled in size across many separate edits, ran a full coherence
audit rather than adding another feature - the Linux lesson being that combinatorial
surface drifts out of coherence without an automated check. Audited:

- all 25 dispatch entries -> defined function (all resolve, no orphans)
- every declared parameter is used (all 40+ referenced)
- every menu action + safe-exclusion name maps to a real module (all valid)
- every Add-Undo record is well-formed (correct Kind, required fields present)
- every verify Test-RegInvariant path corresponds to a Set-Reg in the script
- every safety-critical module has a harness model; declarative reg-write modules
  correctly do not (no branching to test - they get undo+dry-run via Set-Reg)

ONE real drift found and fixed: version strings. The banner and undo filenames said
v2.2 but the help .SYNOPSIS and every .EXAMPLE still said v2.1 / referenced the old
filename Harden-Windows11-v2.1.ps1. Unified to v2.2 and added a "WHAT CHANGED IN
v2.2" section so the help reflects what the script now actually does (was lying by
omission about the menu, undo, USB, etc). This is the bug 26 family - documentation
asserting a state that does not match reality.

Also noted: my audit regex initially false-positived three verify checks as "not
set" because they use a $uac/$lsa variable path my literal-string regex missed. The
checks are correct; the audit was too strict - the bug 29/30 cry-wolf family, even
in a throwaway audit. Fixed the reading, not the script.

Made the coherence audit a STANDING harness check (MODEL 12): dispatch resolves,
menu maps, no stale version refs - so this drift cannot silently return. Twenty-one
sabotages now, all caught.

## Native -SelfTest in the ps1 + run-tests.bat (twelfth pass)

The Python harness (0wintest-logic.py) is the verified reference but needs Python,
which Windows boxes lack by default. So the ps1 now has a native `-SelfTest` that
runs with no dependencies and no admin, and changes nothing:
  (A) decision-logic truth tables ported faithfully from the verified Python
      (lockout guard, egress pin, verify verdicts, spooler gate, menu activation,
      USB safety, device-install values), and
  (B) a static self-audit against the script's OWN source - coherence (dispatch
      resolves), no stale v2.1 filename references, and the dry-run-promise scan
      (no undisclosed destructive Invoke-Step). The (B) checks test the REAL file,
      so they are self-verifying even without a PowerShell runtime here.

`-SelfTest` runs BEFORE the admin check (it needs none) and exits 0 on all-pass.
I cross-checked every ported expected value against the verified Python logic - all
faithful (one apparent mismatch was a Python `and`-returns-operand quirk in the
cross-check, not a port error; PowerShell yields a proper $false there).

run-tests.bat runs three layers, each degrading cleanly: (1) native -SelfTest
always, (2) the Python reference + --sabotage if python is present, (3) the Pester
suite if Pester is installed. Exit 0 only if every layer that ran passed. Running
both (1) and (2) is deliberate: any divergence between the PS port and the verified
Python reference surfaces immediately on the box.

Process note: my crude brace-counter false-alarmed on this change because it does
not strip <# #> block comments (I had expanded the help block). The file was fine;
the CHECKER was wrong - a stronger block-comment-aware count confirmed balance. Same
lesson as always: a checker is only as trustworthy as its own correctness. Switched
to the stronger check.

## FIRST REAL-BOX RUN - three findings (thirteenth pass)

run-tests.bat was run on the actual Windows box (D:\...\win 11). All three layers
reported problems; all three were real and are fixed:

1. PARSER BUG in the ps1 (the important one). Line 1053, the Bloatware undo note,
   used C-style escaping: \" (backslash-quote) and `$(...) inside a double-quoted
   string. That is invalid PowerShell - the parser threw "Unexpected token" and
   "hash literal was incomplete", which ABORTED the whole -SelfTest. My brace/
   quote counters never caught it because they do not parse PowerShell the way
   PowerShell does. Fixed: rewrote the note as a plain single-quoted string
   (doubled '' for literals, no escaping games). Added a PARSER-HAZARD scan to the
   harness (MODEL 12) that greps for C-style \" mid-string, plus a sabotage
   (parser_hazard). This is the class of bug only a real runtime (or a targeted
   scan) can find - the Windows equivalent of why the Linux VM run mattered.

2. Pester 3.4.0 (ships in-box) rejected the test file: it used v5-only syntax
   (BeforeAll at top level, Should -Be, Set-ItResult). Rewrote the suite in
   v3+v5-compatible syntax (setup inside Describe, `Should Be`/`Should Match`).
   The most valuable test - 'parses without syntax errors', which runs the REAL
   PowerShell parser - now runs first and would have caught finding #1 directly.

3. run-tests.bat mis-detected the Microsoft Store 'python' alias as a real
   interpreter (`where python` finds the stub; running it prints an install
   message). Fixed: the bat now probes by actually running `python -c "print(1)"`
   and checking the output, skipping cleanly if it is the stub.

Lesson reinforced: the real box is the sshd -T equivalent. Static checks got the
logic right, but only the actual PowerShell parser found the escaping bug, and only
the actual Pester version found the syntax-compat bug. Twenty-two sabotages now.

## Sibling hunt after the parser bug (fourteenth pass)

The box found one C-style-escape parse error (\"). Bug-39 discipline: find the
SIBLINGS of that class before the next round-trip. Swept the whole file for the
related PowerShell string hazards:

FOUND ONE real sibling: L1092, the Guest undo note, used \$_.SID (backslash-
dollar) where L1086 (the Administrator note) correctly used `$_.SID (backtick).
Backslash-dollar is not a parse error but it CORRUPTS the emitted note - it prints
a literal backslash then interpolates $_.SID to empty. Fixed to backtick (defer
the literal into the emitted undo script). Both admin/guest undo notes now consistent.

Extended the harness parser scan to catch \$var too - but NARROWED to the one
context where intent is unambiguous: inside an Add-Undo Undo=/Note= (a string that
becomes emitted code). Everywhere else, \$Name is legitimate ("$Path\$Name" is a
literal path separator plus interpolation), so a blanket \$ scan cry-wolfed on 5
correct registry-path strings. Kept the scan precise rather than fixing a false
alarm into a regression (bug 29/30 lesson, applied to my own checker).

Confirmed CLEAN for the other hazard classes: no here-strings (StringBuilder avoids
that whole indented-terminator class), all $(...) subexpressions balanced, no -f
format placeholder/arg mismatches.

Net from the real-box round-trip: 1 parse bug + 1 emitted-code corruption bug, both
of the same class, both now scanned-for. Twenty-two sabotages, all caught.

## Single-file: tools embedded in the ps1 (fifteenth pass)

Per the single-file philosophy (same as 0harden.sh), the companion tools are now
EMBEDDED inside the .ps1 as base64 and extracted on demand:
  .\Harden-Windows11-v2_2.ps1 -ExtractTools [-ExtractPath <dir>]
writes 0wintest-logic.py, run-tests.bat, Harden-Windows11.Tests.ps1, and README.md
next to the script. Needs no admin, changes no system state, runs before the admin
check.

Why base64 rather than raw here-strings: base64's alphabet has no quotes,
backslashes, or $ - so the embedded blobs cannot carry the quote/escape parser
hazards that the real box just caught twice. The blobs round-trip byte-for-byte
(verified by sha256 against the originals). The 4 here-string terminators are all
at column 0 (the indented-terminator parse hazard I flagged earlier - checked).

Drift guard: the embedded copies could go stale vs the real files. Added an
embed-drift check to MODEL 12 - it decodes each blob and sha256-compares to the
sibling file, with an embed_drift sabotage. So a stale embed turns a test red. (A
file cannot embed itself, so the check skips the ps1-in-ps1 case; the .py embeds
the other three, and the ps1 embeds all four including the .py.)

Process note: I briefly hit a self-inflicted ordering slip - re-embedding twice in
one workflow left a mismatch. Not a code bug; a single clean re-embed fixed it, and
the drift check now makes that mistake self-evident. The ps1 is now genuinely one
file you can ship; everything else reconstitutes from it.

## Second real-box run - self-test PASSES, three fixes (sixteenth pass)

The native -SelfTest ran clean on the box: ALL 34 PASSED. That is the first
end-to-end confirmation on real hardware that the script parses and its decision
logic holds (the parser fix from last round worked). Three remaining issues, all
fixed:

1. CONSOLE MOJIBAKE: "SELF-TEST â€”" instead of "SELF-TEST -". The script had 15
   em-dashes (U+2014); the Windows console (Windows-1252) garbled the UTF-8. Fixed
   by replacing all em-dashes with " - " (also honours the no-em-dash preference).
   The script is now pure ASCII (0 non-ASCII chars). Added a non-ASCII guard to
   MODEL 12 with a sabotage, so mojibake cannot recur.

2. STALE FILES ON THE BOX: the Pester error pointed at "BeforeAll at line 40",
   but the rewritten (v3-compatible) Tests file has no BeforeAll - the box was
   running an OLD copy on disk. Same for the Python-stub detection in the bat.
   Root cause: run-tests.bat runs whatever files are next to it, which can be
   stale. Fixed: the bat now self-extracts the current tools from the .ps1
   (single source of truth) as step [0/3] before testing, so it never runs a
   stale copy.

3. SELF-OVERWRITE HAZARD in that fix: a running .bat cannot safely overwrite
   ITSELF. Added -ExtractExcept to Invoke-ExtractTools; the bat's self-refresh
   excludes run-tests.bat so it never clobbers the running file.

The Python "FAILED" was the stale bat again (the Store-stub probe was in the new
bat, not the one on the box). Once the box runs the refreshed bat, python skips
cleanly and Pester runs the v3-compatible suite.

Lesson: embedding tools in the single file was the right call - it makes "stale
copy on disk" fixable by self-extraction. The remaining box step is -DryRun on a
snapshot (the cmdlet-shape / sshd -T equivalents). Twenty-three sabotages now.

## Idempotency by double-run - the last method (seventeenth pass)

Applied the one bug-hunting method not yet used on Windows: "run harden twice, does
anything throw, duplicate, or lie?" The full version needs the box, but the static
form - reading every state-changing op for re-run safety - found real answers:

RE-RUN SAFE (verified by reading):
- All 4 New-NetFirewallRule calls are existence-guarded (if -not Get-NetFirewallRule
  ...). A duplicate DisplayName does NOT error in Windows - it silently creates a
  SECOND rule - so this guard is what stops rule accumulation. Added a static scan
  (MODEL 12) that fails if any New-NetFirewallRule is unguarded, with a sabotage.
- Set-Reg/New-ItemProperty -Force, Set-Service, Set-NetFirewallProfile, auditpol,
  Set-SmbServerConfiguration, ASR Add-MpPreference-by-ID: all idempotent (set/
  overwrite, no accumulate).
- BitLocker enable is guarded by an already-protected check (ProtectionStatus -eq
  'On' skips enable), so a re-run does not add a duplicate TPM+PIN protector.
- Set-Reg skips undo recording for no-op sets, so run #2's undo is near-empty and
  run #1 still reverts to pristine (verified earlier).

ONE real issue fixed: the BitLocker recovery-key file is timestamped, so every run
drops ANOTHER plaintext copy of the key in the backup dir. Each is valid, but N
copies = N decryption paths for a stolen disk (compounds bug 39). Now the escrow
step counts prior key files and adds a ManualStep to prune stale ones.

That completes the bug-hunting method catalog on Windows: reading-for-families,
argument fuzzing, artifact attacks, promise testing, coverage-diff, refactoring,
attack-own-feature, coherence audit, and now idempotency. Twenty-four sabotages.

## Third box run - the stale-file problem, solved at the root (eighteenth pass)

The self-test ran clean (34/34, no mojibake - the ASCII fix worked). But the Pester
BeforeAll error was STILL there, byte-identical, and the box output had NO [0/3]
line - proving the box was running an OLD run-tests.bat that predates the self-
refresh step. Same stale-file class, now hit THREE times: the fix ships in the file,
but the box runs a stale copy on disk. The self-refresh could not fix a stale BAT
because the bat is the stale thing (chicken-and-egg).

ROOT-CAUSE FIX: stop depending on files on disk at all.
- Added -PesterTest to the .ps1: it extracts the Pester suite to a TEMP dir from
  the embedded copy, runs it there, and cleans up. There is no stale-file surface
  - the .ps1 is the single source of truth, and it is always current because it is
  the file you actually run. Works with Pester 3.4 (in-box) and 5; retries without
  -Show for v3; skips cleanly if Pester is absent.
- Rewrote run-tests.bat as a THIN LAUNCHER: it only calls the .ps1's -SelfTest and
  -PesterTest. Even if the bat itself is stale, the .ps1 it invokes is current. The
  Python layer (and its Store-stub noise) is removed from the runner - it stays a
  dev tool via -ExtractTools.

Also finished de-mojibaking: the README still had em-dashes and an arrow (U+2192);
all four files and the ps1 are now pure ASCII (0 non-ASCII).

Lesson, three times paid: for a tool that gets copied around and re-run, "current
logic in a file the box does not run" is worthless. The single-file .ps1 with
embedded tools and in-script test modes removes the entire stale-file failure mode.
The box now only ever needs the ONE .ps1. Twenty-four sabotages, all caught.

## Consolidated to 2 files, menu-driven, no flags (nineteenth pass)

The box uploads confirmed the diagnosis exactly: the uploaded ps1 IS current (2869
lines, has Invoke-PesterTest), but the uploaded run-tests.bat and Tests.ps1 were the
OLD ones - the bat still ran the stale Tests sidecar. So the fixes were always right;
the sidecars on disk were stale.

Per the request, collapsed the deliverable to exactly TWO files the user handles:
  - Harden-Windows11-v2_2.ps1   (the whole tool; embeds the rest)
  - run-tests.bat               (24 lines; just launches the ps1 menu with -Menu)

No flags required anymore. The menu gained a "run self-tests" branch (Show-TestMenu):
  6 -> 1  quick self-test  (native logic + static audit)
  6 -> 2  full Pester run  (-PesterTest: extracts a FRESH suite to temp, runs there)
  6 -> 3  unpack tools     (regenerate the py/Tests/README/bat beside the script)
Menu numbering: advanced moved into help (7); extra-security is 5; tests are 6.

Verified the end-to-end no-flags path by simulating -PesterTest: extracted the
EMBEDDED Tests to a temp dir - it is the v3-clean file (line 40 = It '...', no
top-level BeforeAll, 27 'Should Be', zero real v5-only syntax). So on the box's
Pester 3.4 it runs clean, and it never touches the stale sidecar.

The stale-file failure mode is now structurally gone: the bat only launches the
ps1; the ps1 runs tests from its own embedded copy in temp. Two files, and only the
ps1 truly matters. Twenty-four sabotages, all caught, pure ASCII, clean green.

## No-exfil / privacy by default (twentieth pass)

Per request: prevent AV report submissions, telemetry, memory-dump/crash-report
submissions, sample sending, and like items - BY DEFAULT. These land in the two
baseline modules (Defender + Privacy), so plain "harden" applies them.

DEFENDER - flipped from the original protection-first defaults:
- Was: MAPSReporting Advanced + SubmitSamplesConsent SendSafeSamples (sends
  telemetry AND files to Microsoft). Now default: MAPSReporting Disabled +
  SubmitSamplesConsent NeverSend, plus policy-registry SpynetReporting=0,
  SubmitSamplesConsent=2, LocalSettingOverrideSpynetReporting=0.
- Honest tradeoff noted (bug 26): this reduces cloud-delivered protection;
  CloudBlockLevel is inert without MAPS. -CloudProtection re-enables the old
  behaviour for users who want max protection over privacy.

PRIVACY - added outbound-data controls:
- Windows Error Reporting off + DontSendAdditionalData + AutoApproveOSDumps=0
  (no crash reports, no memory dumps sent).
- CEIP off, App Impact Telemetry (AITEnable) off, app inventory off.
- Feedback frequency zero + DoNotShowFeedbackNotifications.
- Typing/inking data collection off (AllowLinguisticDataCollection,
  RestrictImplicit Ink/Text Collection).
- Cloud clipboard sync + activity upload off. DisableOneSettingsDownloads.

Verify gained checks for telemetry, WER, DontSendAdditionalData, CEIP, AIT, and
Defender SpyNet-off (INFO when -CloudProtection is used).

SELF-INFLICTED BUG caught + fixed: my Python heredoc injection doubled every
backslash in the new registry paths (HKLM:\\SOFTWARE instead of HKLM:\SOFTWARE
- 74 sequences). A double-backslash registry path is wrong and Set-Reg would
mishandle it. Caught by comparing raw backslash COUNTS against known-good existing
lines (not repr display, which was misleading me). Collapsed all 74 to single;
whole-file sweep confirms 0 double-backslash HK paths remain. Classic "the tool
that edits the file introduced the bug" - caught before shipping by byte-level
verification, the same discipline that caught the parser bug on the box.

## Network services lockdown: SMB / printer / RDP / remote-mgmt (twenty-first pass)

Per the user's choices (aggressive baseline): new Invoke-Mod-NetworkServices, in
the BASELINE (applied by "harden"):
  - SMB SERVER off (LanmanServer disabled) AND SMB CLIENT off (LanmanWorkstation +
    mrxsmb20). Loud ManualStep: breaks \shares, mapped drives, domain GPO/SYSVOL.
    Escape hatch: -KeepSMBClient.
  - Print Spooler FULLY disabled (no printing), unless shared printers present
    without -Force. Escape hatch: -KeepPrinting (keeps local print, kills remote
    RPC endpoint + restricts Point-and-Print to admins).
  - Remote Desktop service (TermService) stopped (RemoteAccess module already
    denies logons + firewall; this adds the service stop). Guarded vs live RDP.
  - WinRM / PS-Remoting disabled (service + firewall + AllowAutoConfig=0). Guarded.
  - Remote Assistance: fAllowUnsolicited=0 (RemoteAccess sets fAllowToGetHelp).
  - OpenSSH sshd disabled IF present.
  - Discovery: SSDPSRV, upnphost, FDPHost, FDResPub, WMPNetworkSvc + Network
    Discovery firewall group.
  - Legacy IF present: Telnet, FTP (FTPSVC/MSFTPSVC), SNMP/SNMPTRAP, simple TCP.

Extra-security > 6 (Show-NetworkAllowMenu): allow/disable SMB, printer, RDP.

Helpers added: Disable-ServiceSafe / Enable-ServiceSafe (installed!=running guard,
prior StartMode captured for undo). All changes route through Set-Reg/Invoke-Step
with undo records -> fully reversible.

DEDUP: RemoteAccess already owned RDP fDeny + firewall + fAllowToGetHelp, so
NetworkServices does NOT redo those - it adds only TermService stop and
fAllowUnsolicited. Avoided a two-modules-fight-over-one-setting coherence smell.

SELF-INFLICTED BUG caught: I used the ? : ternary (PowerShell 7+ ONLY; the box
runs Windows PowerShell 5.1). It would have parse-errored on the box exactly like
the earlier \" bug. Caught by a targeted PS7-syntax scan BEFORE shipping; replaced
with if/else. Also scanned for &&/||/??/?. pipeline operators (none). This is the
"know the target runtime" lesson - 5.1 lacks ternary, null-coalescing, and
pipeline chain operators.

Verify gained service-state checks for SMB server/client, Spooler, WinRM (INFO when
re-allowed). 26 modules now, harness green, pure ASCII, no double-backslash.

## Second guide review - fresh coverage-diff (twenty-second pass)

Re-reviewed the same "Win11 25H2 Aggressive Hardening" guide against the CURRENT
(much larger) script. Most of what looked missing was a FALSE NEGATIVE from
over-specific greps - already covered: sudo (SurfaceReduction), VBS/HVCI
(DeviceGuard), BitLocker XTS, NTLM audit, event-log size, process-creation audit,
Advertising ID (line 992), NetBIOS-off (SetTcpipNetbios line 902), SMB signing,
ROCA, ASR BYOVD, ScriptBlock logging, Activity History, Copilot, LLMNR.

GENUINELY missing, added (small, low-breakage):
  - LimitDumpCollection=1 + LimitDiagnosticLogCollection=1 + DisableTelemetryOptIn
    SettingsUx=1 (Privacy) - completes the no-exfil work: no crash-dump/diag-log
    collection, and hides the telemetry opt-in UI so it cannot be re-enabled via
    Settings.
  - Xbox/gaming services disabled (NetworkServices, only-if-present): XblAuthManager,
    XblGameSave, XboxGipSvc, XboxNetApiSvc, GamingServices(Net).

CORRECTLY NOT ADDED (documented, unchanged from the first review):
  - WSUS/DODownloadMode: hardcoded internal server URL breaks updates off-domain.
  - RemoveWindowsStore / AppInstaller: breaks winget/Store; enterprise choice.
  - LAPS: reg-only policy is inert without the AD/Entra backend; manual item.
  - The guide's Set-ItemProperty -PropertyType bug still makes its whole script
    body throw - it has never been run as written.

Coverage-diff on a grown codebase is mostly a FALSE-NEGATIVE hunt: the value is
confirming the big list is already covered, and catching the 2-3 genuine gaps.
Harness green, pure ASCII, no double-backslash, no PS7 syntax.

## FIRST FULL APPLY ON REAL HARDWARE - clean pass (twenty-third pass)

The user ran menu 2 (harden) on Win11 Home 22631 / PowerShell 5.1. The ENTIRE
baseline applied with ZERO [Failed] and zero parse errors. Everything from the
recent passes ran correctly on hardware:
  - NetworkServices: SMB server+client off, Spooler off, TermService off, WinRM
    off, discovery services off, Xbox off. installed!=running guard worked -
    sshd/Telnet/FTP/SNMP/GamingServices all "not present; nothing to disable"
    (no false failures).
  - No-exfil Privacy block: Defender cloud reporting OFF, sample submission NEVER,
    WER/dumps off, CEIP/AIT off, typing/inking off, LimitDumpCollection etc.
  - Edition-floor logic correct: warned "Core enforces min telemetry 1" instead
    of falsely claiming telemetry=0 on Home (bug 36 family working as designed).
  - Defender third-party/Tamper -> WARN not FAIL (INCONCLUSIVE logic correct).

TWO observations:
1. A console run-together artifact (RemoteAccess line + Services banner on one
   line) - investigated: Write-Log uses Add-Content per line, Write-Section leads
   with a blank line, no stray \r, file has 0 CRLF. It is a live-console render
   artifact under fast Write-Host streaming, NOT a code bug. The LOG FILE is
   clean. Did NOT "fix" a non-bug (bug 29/30 lesson).
2. Added a genuinely useful thing the run motivated: a post-run CONNECTIVITY
   RESTRICTED banner in Write-RunSummary that checks the ACTUAL resulting service
   states (LanmanWorkstation/Spooler/TermService/WinRM = Disabled) and lists what
   is now off at the END, so the SMB/RDP/print consequences are not lost mid-log.
   Points to menu 5 and the undo script.

This is the milestone: the current code parses and applies correctly on the target
runtime. Two files, harness green, pure ASCII, no double-backslash, no PS7 syntax.

## Audit-readiness: gap-hunt + inline notes + undo relocation (twenty-fourth pass)

User is heading into an audit and asked for (a) undo next to the ps1, (b) a gap
hunt, (c) inline audit notes per item.

UNDO LOCATION: was hardcoded to $env:SystemDrive (C:\). Now writes next to the
.ps1 (Split-Path $PSCommandPath) with a writability probe + fallback to C:\ if the
script dir is read-only. Travels with the tool, easier to find.

GAP-HUNT vs CIS L1/L2 / MS Security Baseline / DISA STIG. Real gaps found and
CLOSED, each with an INLINE audit-framework citation in the source:

  Credential module (added, high value):
    - WDigest UseLogonCredential=0  <- THE big one: stops cleartext passwords in
      LSASS (Mimikatz sekurlsa::wdigest). Guaranteed audit finding if missing.
    - LimitBlankPasswordUse=1, EveryoneIncludesAnonymous=0, RestrictNullSessAccess,
      empty NullSessionPipes/Shares (anonymous SMB enumeration).
    - LDAPClientIntegrity=1 (LDAP signing), Kerberos SupportedEncryptionTypes
      AES-only (no RC4/DES), CachedLogonsCount=4.
  Network module (added): DisableIPSourceRouting=2 (v4+v6), EnableICMPRedirect=0,
    NoNameReleaseOnDemand=1.
  NEW Invoke-Mod-AccountPolicy (baseline): password length 14 / max-age 365 /
    min-age 1 / history 24, lockout 5/15/15, complexity ON + reversible-encryption
    OFF. Uses `net accounts` and `secedit` (these are SAM/LSA policy, NOT registry).
    Dry-run SAFE: narrates "WOULD run" instead of executing.
  NEW Invoke-Mod-LockScreenUI (baseline): AlwaysInstallElevated=0 BOTH HKLM+HKCU
    (classic LPE), lock-screen camera/slideshow off, InactivityTimeoutSecs=900
    (auto-lock), DontDisplayLastUserName, CTRL+ALT+DEL required.

Every new item carries an inline comment naming the control family (CIS 1.1.x,
18.9.x, STIG WN11-*) so an auditor reading the source sees the mapping directly.

Verify gained 6 new invariant checks (WDigest, blank-pw, AlwaysInstallElevated,
source routing, lock-screen camera, auto-lock). 28 modules now.

DISCIPLINE NOTES:
  - Used a RAW python string (r''') for the injection this time -> ZERO double-
    backslash (the bug from the no-exfil pass). Learned.
  - Checked the foreach/Invoke-Step closure: Invoke-Step runs & $Action
    SYNCHRONOUSLY, so $na is not a deferred-capture loop-closure bug.
  - net accounts .Split(' ') on single-token args is correct.
  - AccountPolicy/secedit are the first NON-registry writes; both dry-run guarded.

Harness green, pure ASCII, no PS7 syntax, no double-backslash. This is the
audit-prep pass: framework-mapped controls with source-level citations.

## Undo-location + audit-gap hunt with inline notes (twenty-fourth pass)

User asks: (1) put undo next to the ps1, (2) gap-hunt + inline audit notes ahead
of an audit.

UNDO LOCATION: Write-UndoScript now writes Harden-Win11-UNDO_<stamp>.ps1 into the
SCRIPT's own directory (Split-Path PSCommandPath) instead of C:\, with a
writability probe and fallback to the system drive if the script dir is read-only.

AUDIT GAP-HUNT (CIS L1/L2, MS Baseline, DISA STIG): checked ~26 controls. Much was
ALREADY covered from prior passes: AccountPolicy module (password length/age/
history + lockout via net accounts; complexity + ClearTextPassword via secedit;
full CIS 1.1.x/1.2.x citations inline + domain-GPO caveat), LockScreenUI module
(AlwaysInstallElevated HKLM+HKCU, NoLockScreenCamera/Slideshow, InactivityTimeout
auto-lock, DontDisplayLastUserName, DisableCAD), Network (DisableIPSourceRouting
v4+v6, EnableICMPRedirect off), plus RestrictAnonymous, RDP NLA, SMB signing, etc.

GENUINELY NEW - credential audit-hardening block (inline CIS/STIG note per item):
  - WDigest UseLogonCredential=0 - stops CLEARTEXT passwords cached in LSASS (the
    Mimikatz sekurlsa::wdigest target). Highest-impact item; guaranteed finding
    if missing.
  - LimitBlankPasswordUse=1, EveryoneIncludesAnonymous=0, RestrictNullSessAccess=1,
    empty NullSessionPipes/Shares, LDAPClientIntegrity=1, Kerberos AES-only,
    CachedLogonsCount=4.
Added verify checks for WDigest, blank-pw, anonymous, null-session, LDAP signing.

Used a Python RAW-string heredoc for the injection this time, which AVOIDED the
double-backslash bug from the no-exfil pass. Verified: 0 double-backslash, 0 non-
ASCII, 0 PS7 ternary, balanced. 71 verify checks, 28 dispatch modules, harness
green. Every new item carries an inline framework/control citation so the audit
walkthrough is self-documenting.


## Extra network lockdown + GAP DETECTION of pre-existing weaknesses (25th pass)

Two asks: lock down more network resources, and DETECT pre-existing weaknesses to
show the user as follow-up items (not just verify our own changes).

NETWORK LOCKDOWN (NetworkServices module): added mDNS off (EnableMDNS=0 - the third
name-poisoning protocol with LLMNR+NetBIOS), NetBIOS at the REGISTRY level too
(NetbiosOptions=2 per interface, survives adapter re-add), PNRP/peer-networking
(PNRPsvc/p2psvc/p2pimsvc/PNRPAutoReg), and Link-Layer Topology (lltdsvc + firewall
group). All via Disable-ServiceSafe (installed!=running guard, undo captured).

NEW CAPABILITY - GAP DETECTION: a read-only scan in the Verify module that finds
weaknesses the tool did NOT create and should not silently auto-fix, reported with
a new [GAP] verdict and collected into a FOLLOW-UP list in the run summary:
  - enabled local accounts with no required password (blank-password)
  - AutoAdminLogon enabled (+ cleartext DefaultPassword in registry)
  - Guest account enabled
  - more than 2 local Administrators (lists them for review)
  - enabled accounts with non-expiring passwords
  - unquoted service paths with spaces (priv-esc vector)
  - SMBv1 feature still installed
Each is a FINDING for the user to action, not an invariant we assert - exactly what
an auditor wants surfaced. Added [GAP] to Write-Check and a $Script:GapFindings
accumulator; the summary prints a red FOLLOW-UP block listing them.

Harness gained MODEL 13 (gap-detection logic: unquoted-path regex truth table +
blank-password verdict) with a gap_off sabotage. Getting MODEL 13 wired took FOUR
self-inflicted fixes, each caught by the harness's own checks before shipping: a
phantom sabotage-only check, editing the wrong file, forgetting to register the
model in TESTS, and an over-escaped regex from the heredoc. The embed-drift guard
also correctly flagged the stale embedded copy each time the .py changed. The
system catching my own mistakes is the point. 26 sabotages, 79 assertions, clean
green, pure ASCII, no double-backslash.


## Audit evidence report + a real bug found (twenty-fifth pass)

Reframed "keep on it" around the upcoming AUDIT: the highest-value addition is not
another control but making the tool produce AUDIT EVIDENCE.

REAL BUG FOUND (bug-26 / coherence family): Write-Check maps state GAP -> Add-Result
Status='GAP', but Add-Result's ValidateSet was ('Applied','Skipped','Failed',
'Audit','Info','Pending') - NO 'GAP'. So any of the 7 live GAP callsites (enabled
account w/o password, AutoAdminLogon on, Guest enabled, multiple admins, non-
expiring passwords, unquoted service paths, SMBv1 present) would THROW a ValidateSet
violation at runtime - exactly WHEN the box has a gap an auditor cares about. It
never showed on the clean box because no gap fired. Fixed: added 'GAP' to the set.
Added a harness coherence check (status_mismatch sabotage) that statically compares
every status Write-Check can emit against Add-Result's ValidateSet, so this class
cannot recur.

NEW FEATURE - Write-AuditReport (-AuditReport, or menu 3 -> prompt): runs the
read-only Verify, then exports a self-contained HTML evidence file next to the .ps1:
system identity + timestamp + a control/state/detail table, color-coded PASS/FAIL/
PENDING/GAP/INFO with a summary banner. Reflects ACTUAL live state (re-reads the
registry/services), ACL-locked because it can name gaps, changes nothing. Turns the
existing verify pass into an audit deliverable that maps to the inline CIS/STIG
citations.

STRUCTURE-CHECK UPGRADE: the report uses a @"..."@ here-string containing CSS { }.
My brace counter did not understand here-strings - it passed only because the CSS
braces happened to balance. Upgraded the check to SKIP here-string bodies (@"..."@
and @'...'@), so it now validates real code structure rather than passing by luck.
Confirmed real balance 0 with the here-string-aware counter.

Verified: 0 non-ASCII, 0 double-backslash, balanced (here-string-aware), 26
sabotages caught, drift clean, ALL PASS.


## Third guide review - 4-tier framework coverage-diff (twenty-sixth pass)

Reviewed a new well-structured guide organized around a 4-Tier framework (Light /
Moderate-CIS-STIG / Aggressive-ZeroTrust / Extreme-airgap). Used its OWN tiering as
the triage lens: Tier 1-2 low-breakage -> baseline; Tier 3-4 breaking -> opt-in.

Coverage-diff: ~28 controls, most already covered (LLMNR, NetBIOS per-adapter, mDNS,
LanmanServer/Workstation disable, RemoteRegistry, RDP NLA, SMB signing, outbound
block, NoNameReleaseOnDemand, IP source routing, ICMP redirect).

ADDED to baseline Network module (Tier 1-2, low breakage, inline tier+Domain cite):
  - EnableNetbios=0 at Dnscache layer (belt with per-adapter)
  - AllowInsecureGuestAuth=0 (no unauth guest SMB fallback)
  - IPv6 transition tech OFF: Teredo/ISATAP/6to4/IP-HTTPS (synthetic tunnels that
    bypass IPv4 firewall/IDS - exfil corridors; no impact on native v4/v6)
  - RPC RestrictRemoteClients=1 - deliberately 1 (auth WITH exceptions) NOT the
    guide's 2 (no exceptions), which breaks legit services on standalone
  - DODownloadMode=0 (Delivery Optimization peering off)
  - NC_ShowSharedAccessUI=0 (mobile hotspot / ICS off - no rogue bridging)

ADDED opt-in (extra security > 7, Invoke-AggressiveNetwork, confirmed + Tier 3-4
breakage warned inline):
  - Admin shares off (AutoShareWks + AutoShareServer) - breaks PsExec/MECM/scanners
  - UNC hardening SYSVOL/NETLOGON (RequireMutualAuthentication+Integrity) - domain
    only, inert-but-harmless standalone; ManualStep warns to verify DC SMB signing

DECLINED with reasons (inline/handover): DoHPolicy=3 REQUIRE (breaks all DNS if DoH
server unreachable - we keep EnableAutoDoh=2 opportunistic), W32Time hardcoded
NtpServer (env-specific), adapter-binding strips / MAC randomization / SMB2-disable /
full outbound-block / local-rule-merge-off (Tier 4, need GPO/whitelist or break
modern SMB). The guide's SMB2=0 would break all modern file access.

BUG-AVOIDANCE: the UNC key NAME is legitimately \\*\SYSVOL (backslashes are part
of the name, not a path separator). Verified byte-exact (\ \ * \ SYSVOL) rather
than letting the double-backslash collapser touch it. Used raw-string heredocs
throughout -> 0 double-backslash HK paths. Added 5 verify checks for the new items.
Balanced (here-string-aware), 0 non-ASCII, 0 PS7, 26 sabotages, ALL PASS.


## Self-test coverage audit - test the tests (twenty-seventh pass)

Honest read: the script grew ~2100 -> 3595 lines across many passes, but the
self-test/harness coverage did NOT grow proportionally. Risk: a new module has a
branch bug no test drives (the GAP/ValidateSet bug last pass proved this - it sat
undetected because nothing exercised the GAP path).

Measured coverage: ranked all 28 modules by decision-branch count (if/switch/guard/
foreach). NetworkServices (29 branch points) is the newest + highest-branch module
and its SMB-client-Keep / printer-safety-stop / installed!=running logic was only
PARTIALLY modeled (the old SurfaceReduction spooler model covered a different path).

ADDED MODEL 13 to the Python harness - NetworkServices decision logic:
  - SMB client default->DISABLE, -KeepSMBClient->KEEP
  - Spooler -KeepPrinting->KEEP_LOCAL, shared+no-force->SKIP (safety stop),
    shared+force->DISABLE, no-shared->DISABLE
  - Disable-ServiceSafe: present->ACT, absent->SKIP (installed!=running)
With 3 sabotages (keepsmb_ignored, shared_printer_ignored, absent_service_acts).
Mirrored all 6 into the NATIVE -SelfTest too, so the box shows them (self-test
now ~40 checks, dynamic count - no hardcoded total to drift).

THREE self-inflicted bugs found + fixed while doing this (the meta-lesson: even
writing tests introduces bugs):
1. Used section() - no such function; the harness prints headers with print().
2. MODEL 13 number COLLISION with the pre-existing gap-detection model. Renumbered
   gap-detection -> MODEL 14. Each of 1-14 now unique.
3. The KEY bug: my new sabotages showed NOT CAUGHT in the --sabotage loop. Cause:
   the real SABOTAGES iteration list (line ~731) is SEPARATE from the one I first
   edited, AND my test calls did not thread SABOTAGE through (the existing models
   use a lambda: sp = lambda **k: fn(**k, SABOTAGE=SABOTAGE)). Fixed both - also
   discovered status_mismatch (from a prior pass) was likewise missing from the
   real list. Now 30 sabotages, all caught.

Also fixed a Python SyntaxWarning (invalid escape '\$' in a check() display
string) so the harness runs warning-clean.

30 sabotages, 88 assertions, native self-test ~40, balanced, ASCII, no double-
backslash, ALL PASS. The tool's own tests now cover its highest-risk module.


## Inline audit documentation - every item and section justified (28th pass)

User: each item + section needs inline documentation with justification, for use
DURING an audit. The key insight: the -Item label is what appears as the CONTROL
NAME in the log, CSV, and the -AuditReport HTML - so a good -Item is audit
evidence, not just a code comment.

DID:
- Added -Item audit labels to 34+ previously-bare Set-Reg lines. Set-Reg lines
  with a human-readable -Item label: 133 -> 115 labeled (86%; the rest are loop
  bodies or var-path helpers that share one label). Each label names the control
  in plain language (e.g. 'UAC enabled (EnableLUA)', 'LLMNR disabled', 'WDigest
  cleartext credential caching OFF').
- Added a '# --- AUDIT:' section-header justification to EVERY setter module (24
  modules): 2-4 lines each stating what the control family is, why it matters
  (the threat it addresses), and the framework mapping (CIS/STIG/MS Baseline).
  e.g. Credential = 'anti-Mimikatz/anti-relay core', Audit = 'the FORENSIC
  EVIDENCE layer - without it an intrusion leaves no trace'.
- Verify module now documents its audit role and points to -AuditReport.

So the ps1 now reads as its own control-mapping document: an assessor can open it,
read each section's justification, and see each item's control name + inline cite -
and the same -Item text flows into the HTML evidence report. The source IS the
audit narrative.

No logic changed - pure documentation. Verified: balanced (here-string-aware),
0 non-ASCII, 0 double-backslash, coherence check still green (it reads source but
comments do not affect dispatch/menu maps), 30 sabotages, ALL PASS.


## Operational lifecycle: temporary self-reverting unlocks (29th pass)

User insight: a locked-down box still has to LIVE - connect to a hotel captive
portal, print at a client site, adopt a new USB dongle, reach a share - then
re-lock. The danger with the existing 'allow' toggles is they are PERMANENT: you
do the job and forget to re-lock, leaving the box weakened. Built a temporary,
self-reverting unlock subsystem around the user lifecycle.

DESIGN (PS 5.1, no daemon):
- Invoke-Unlock <area> -Minutes -Reason: records ORIGINAL state to a locked JSON
  state file (.harden-unlocks/, ACL'd via Protect-Directory), applies the minimal
  change, and schedules an auto-relock via schtasks (survives logoff).
- Areas: captiveportal (allow DNS/HTTP/HTTPS out for wifi login - narrowest),
  printing (Spooler), smbclient (reach shares), rdp, winrm.
- Invoke-Relock <area|all>: restores from saved original state, clears state +
  task. -Relock is ALSO what the scheduled task calls (works non-interactive).
- Expire-StaleUnlocks: on every launch, re-lock anything past expiry (covers a
  laptop that was asleep when the task should have fired). Belt-and-suspenders.
- Invoke-AdoptUSB: DIFFERENT - permanently approves a newly-plugged device into
  the USB allowlist (you bought it), logged. Not timed.
- Menu 8 (operational): shows ACTIVE unlocks + minutes remaining, offers unlock/
  adopt/panic-relock-all. Nothing stays open unnoticed.

SAFETY INVARIANTS (modeled as MODEL 15, 3 sabotages):
- minutes clamped [1,480] (a 99999-min unlock that never re-locks = sabotage)
- double-unlock REFUSED (else it clobbers the saved original -> can never relock)
- past-expiry -> re-lock (never_expire sabotage)
- every unlock logged with a reason (audit trail)

BUG the harness caught DURING this build: my captive-portal New-NetFirewallRule
was NOT existence-guarded -> unlocking twice would create duplicate rules. The
idempotency scan (from the double-run pass) flagged it immediately; added the
Get-NetFirewallRule guard. Exactly the value of keeping that scan.

CLI: -Unlock captiveportal -UnlockMinutes 30 -UnlockReason 'hotel'; -Relock all.
33 sabotages, 95 assertions, balanced, ASCII, no double-backslash, ALL PASS.


## Fail-closed audit of the unlock subsystem (30th pass)

Honest risk read: the script nearly doubled this session (~2100 -> ~4050 lines) and
the newest third - audit report, self-test coverage, operational unlocks - has NOT
run on hardware. The unlock subsystem is the operationally RISKIEST code (it toggles
security state on a timer), so rather than add more, I audited MY OWN unlock code
for the one failure that inverts the tool's purpose: leaving the box WEAKENED.

Found and fixed THREE fails-open modes:
1. Save-UnlockState had no failure handling + WRONG ORDER (applied the weakening
   change, THEN saved state). If the save failed, the box was open with NO recorded
   re-lock path -> Expire-StaleUnlocks and relock-all are both blind to it -> it
   NEVER re-locks. FIX: Save-UnlockState now returns bool + verifies a JSON round-
   trip. Invoke-Unlock reordered to CAPTURE -> SAVE (abort if it fails) -> APPLY ->
   ARM. If state cannot be saved, nothing is weakened (fail closed).
2. Register-RelockTask returned nothing; a schtasks failure was a quiet WARN while
   the unlock had already happened. FIX: returns bool; on failure Invoke-Unlock
   logs ERROR + adds a ManualStep telling the user to re-lock manually (and the
   state file's expiry means the next launch re-locks it via Expire-StaleUnlocks).
3. Invoke-Relock removed the state file UNCONDITIONALLY, even if the re-lock threw
   partway - marking an area 'locked' while it might still be open. FIX: wrapped in
   try/catch; state is cleared ONLY on success; on failure the state is KEPT so a
   retry / next-launch re-locks it.

Modeled all as MODEL 15 fail-closed invariants (2 new sabotages): save-fails ->
box UNCHANGED, relock-fails -> state KEPT. 35 sabotages, 99 assertions, ALL PASS.

The principle: a security tool's temporary-weaken feature must fail CLOSED - if any
step of the unlock/relock bookkeeping fails, the safe outcome is 'stays locked' or
'stays recorded-as-unlocked-so-it-gets-relocked', never 'silently open with no
record'. This is the highest-value review I could do on the riskiest new code, and
it is exactly the kind of bug that only shows up when you ask 'what if this step
fails?' rather than testing the happy path.


## Fourth guide review - 24H2/25H2 architectural analysis (31st pass)

Reviewed a deep architectural guide (CIS vs MS-Baseline vs STIG for Win11 24H2/
25H2). Unlike prior settings-lists this named NEW 24H2 mechanisms. Triaged by the
standing rule: standalone-safe + no-brick -> add; needs AD/Intune or bricks -> skip
with the guide's OWN caveat.

ADDED to baseline (low breakage, standalone-safe, inline 24H2 notes):
  - Enhanced UAC / EPP: TypeOfAdminApprovalMode=2 (24H2 token-theft defense; VBS-
    isolates the elevation token, forces creds on secure desktop). Inert-harmless
    pre-24H2.
  - RDP clipboard + drive redirection blocked (fDisableClip / fDisableCdm) - closes
    the remote-session exfil channel (we already had cloud-clipboard off).
  - Edge Enhanced Security Mode (EnhanceSecurityMode=2) - the REPLACEMENT for MDAG
    which 24H2 removed; disables JIT JS on untrusted sites.
  Added verify checks for all three.

ADDED opt-in (extra security, confirmed, guide caveats inline):
  - 8 Windows Protected Print (WPP): WindowsProtectedPrintMode=1 - driverless,
    spooler drops to USER context, kills PrintNightmare + Point-and-Print. Loud
    caveat: DELETES non-IPP queues, blocks third-party drivers, 24H2+ (build-checks
    and warns if <26100). This is the modern answer to our baseline Spooler-off.
  - 9 Disable Bluetooth (STIG): bthserv + advertising/discoverable off. Caveat:
    breaks BT peripherals.

DECLINED with the guide's OWN reasoning (documented):
  - LAPS AutomaticAccountManagement / dMSA logon: inert without Entra/AD backend.
  - Credential Guard / VBS UEFI LOCK: the guide itself calls it a DoS trap (cannot
    disable remotely, needs physical presence). We keep VBS/HVCI WITHOUT the lock.
  - PKINIT SHA-1 deprecation: the guide warns it SILENTLY breaks auth against
    Server 2022 DCs (error 0x3bc4). Too dangerous to auto-apply; noted as a manual
    domain-only consideration rather than a setter.
  - BitLocker AES-256 / pre-boot PIN: already have XTS + TPM+PIN path.

35 sabotages, balanced, ASCII, no double-backslash, no real PS7 ternary, harness
green. The guide's value was mostly confirming our declines are RIGHT (it documents
exactly why UEFI-lock and PKINIT-SHA1 are traps) plus 5 genuinely new 24H2 items.


## PKINIT SHA-1 deprecation (opt-in, guarded) + known-gaps notes section (32nd pass)

Two user asks: (1) add PKINIT SHA-1 deprecation as a lockdown option; (2) add a
notes section to the ps1 about not-done security items and risky items to watch.

PKINIT (extra security 10, Invoke-PKINITHardening):
- Restricts Kerberos PKINIT (smart-card / WHfB cert auth) to SHA-256/384/512,
  refuses SHA-1. Per-algorithm Enabled DWORDs under
  ...Lsa\Kerberos\Parameters\PKInitHashAlgorithms\{SHA1=0,SHA256/384/512=1}.
- OPT-IN ONLY, never baseline (the guide's trap: pre-Server-2025 DCs use SHA-1 for
  the initial PKINIT negotiation; refusing it SILENTLY breaks domain auth, error
  0x3bc4).
- DOMAIN-GUARDED: detects PartOfDomain via Win32_ComputerSystem; on a domain box it
  is a SAFETY STOP unless -Force, with the exact 0x3bc4 warning + 'keep console
  access to revert' guidance. Standalone = inert-but-harmless.
- Fully reversible (Set-Reg captures prior) + ManualStep telling the user to revert
  from CONSOLE if auth breaks.

NOTES SECTION (top-of-file block comment + -Notes flag):
- 81-line 'KNOWN GAPS AND RISKY ITEMS TO WATCH' block after the help header, in
  three parts: (A) security items NOT done and why (LAPS/dMSA need AD; VBS UEFI-lock
  is a DoS trap; full outbound-deny needs a whitelist; WDAC enforcement is a
  deliberate rollout; firmware/physical controls; domain-GPO precedence), (B) RISKY
  items the tool CAN apply and what to watch (PKINIT 0x3bc4, WPP deletes non-IPP
  queues, SMB/Spooler-off, BitLocker PIN vs patching, admin-shares removal, NTLM
  deny, operational unlocks needing a live schtasks test, no-exfil reduces cloud
  protection, edition telemetry floor), (C) inert-but-harmless-on-standalone items.
- Viewable at runtime with -Notes, which extracts the block FROM THE SOURCE so the
  displayed text can never drift from the actual comment.

BUG caught + fixed during this pass: my first -Notes extraction logic broke after
4 lines - the title sits between two '===' banners, and my 'stop at 2nd banner'
counter started ABOVE the title so it tripped on the title's own banners. Fixed to
start AT the title and count the under-title + closing banners. Verified by
simulation it now extracts all 81 lines incl. all three sections.

Balanced (here-string-aware), 0 non-ASCII, 0 double-backslash, 0 real PS7 ternary,
menu cases 1-10 all wired, 35 sabotages, drift clean, ALL PASS. ps1 ~4260 lines.


## Fifth guide review - lifecycle/ASR architecture (33rd pass)

Reviewed a comprehensive lifecycle guide (discover -> detect -> baseline ->
lockdown -> monitor). Coverage-diff showed MOST of it already covered under other
names: unquoted-path detection (have), 4 of 5 named ASR GUIDs (have), Xbox/gaming
(have), DiagTrack (covered via AllowTelemetry policy), discovery services (have).

GENUINELY NEW, added (all standalone-safe, inline notes + verify checks):
  1. Microsoft Vulnerable Driver Blocklist (CI\Config\VulnerableDriverBlocklist
     Enable=1) - anti-BYOVD, blocks known-exploitable signed ring-0 drivers. One
     key, high value. Deliberately placed in BASELINE ASR module, NOT the opt-in
     DeviceGuard (it works independently of full VBS). Verify re-checks it (the
     guide warns adversaries set it to 0).
  2. Windows Recall disable (WindowsAI\AllowRecallEnablement=0 + DisableAIData
     Analysis=1) - 24H2 Copilot+ screen-snapshot archiver; severe privacy/legal/
     exfil risk. Fits our no-exfil posture. Baseline Privacy module.
  3. PSExec/WMI ASR rule (d1e49aac) - the one missing ASR GUID. JUDGMENT CALL: set
     to AuditMode NOT Block, because Block breaks legit remote admin (MECM/SCCM use
     WMI) AND the user's own pentest lateral-movement tooling. Consistent with
     admin-shares being opt-in and Microsoft's own audit-first posture for admin-
     impacting rules. Inline note says flip to Enabled if no PSExec/WMI admin.
  4. Orphaned-service detection (gap-detection / Phase 2) - read-only: flags
     registered services whose binary is MISSING (an attacker who can write the
     expected path hijacks the dormant registration). Skips svchost-shared.

DECLINED (with reasons): service tamper SDDL injection (sc.exe sdset) - a wrong
SDDL can lock out service management; the guide's example is EDR-specific; too
sharp for a general tool. WDAC ISG/Managed-Installer - needs Intune/cloud (we have
audit-mode WDAC). Config-drift scheduled-task monitoring - heavier monitoring
feature adjacent to our audit report; deferred. WbioSrvc/lfsvc/WpnService disable -
WbioSrvc breaks Windows Hello (bad default); cherry-picked only safe discovery
services we already had.

Balanced, 0 non-ASCII, 0 double-backslash, coherence + idempotency + status checks
green, sabotages green. The guide's main value was CONFIRMING our coverage is deep
(most items already present) plus 4 genuinely new items - 2 baseline wins (driver
blocklist, Recall), 1 audited ASR rule, 1 read-only detector.


## Real-box bug: Protect-Directory -Quiet + a new guard (34th pass)

Box run (menu 2 apply) surfaced a real error at launch:
  Protect-Directory : A parameter cannot be found that matches parameter name 'Quiet'.
Cause (bug-26 family): Get-UnlockStateDir calls Protect-Directory -Quiet, but only
Protect-FILE had a -Quiet switch; Protect-DIRECTORY did not. I copied the -Quiet
idiom from Protect-File without checking the other function's signature. It fired on
EVERY launch (Expire-StaleUnlocks -> Get-UnlockStateDir) and printed an ugly error,
though the menu still came up.

FIX: added [switch]$Quiet to Protect-Directory (matching Protect-File's interface;
it also silences the per-launch 'Locked ACL' log line, which was the intent).

NEW GUARD (so this class cannot recur): a harness check that statically verifies
every call to a curated set of internal helpers (Protect-Directory/File,
Save-UnlockState, Register-RelockTask, Enable/Disable-ServiceSafe) uses only
params those functions DECLARE. With a param_mismatch sabotage.

META-LESSON (documented because it matters): my FIRST version of this guard was
broken TWO ways - (1) it matched '-Word' inside comment prose, and (2) the param-
block regex was non-greedy and stopped at the inner ')' of '[Parameter(Mandatory)]'
so it never saw the real params -> it PASSED even with the bug reintroduced. A
checker that cannot catch the bug it exists for is worse than none (bug 29/30). I
proved it by re-injecting the bug into a temp copy and confirming the check missed
it, then fixed it: strip comments first, and capture the param block by BALANCED-
PAREN COUNTING not a non-greedy regex. Re-verified it now catches the exact
Protect-Directory -Quiet bug.

36 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.

REMAINING BOX-TEST VALUE: this was the first real-hardware exercise of the unlock
subsystem's launch path (Expire-StaleUnlocks). The auto-relock schtasks firing is
still the one unverified piece - worth: -Unlock printing -UnlockMinutes 2, watch it
self-relock, confirm menu 8 countdown + menu 3.


## Clean box run + duplicate ASR GUID bug (35th pass)

Second box run (menu 2 apply + menu 3 verify) came back CLEAN: the Protect-Directory
-Quiet error is GONE (34th-pass fix confirmed on hardware), full baseline applied
with ZERO [FAIL], and all recent additions verified live: VulnerableDriverBlocklist
=1, Recall off, Edge ESM=2, Enhanced UAC=2, RDP clipboard off, orphaned-service scan
ran clean. The GAP path also fired correctly (real finding: two enabled accounts
'Rouge'/'MIA' with no password) WITHOUT throwing - confirming the Add-Result 'GAP'
ValidateSet fix works on hardware too.

BUG the run surfaced: the ASR output listed the PSExec/WMI rule TWICE -
  [ok] Block PSExec/WMI process creation (AUDIT only...) [AuditMode]
  [ok] Block process creations from PSExec and WMI commands [Enabled]
Both had GUID d1e49aac. Root cause: that GUID was ALREADY in the ASR array as an
'Enabled' entry; last pass I added a SECOND entry ('AuditMode') because my coverage-
diff grep returned 2 matches which I misread as the guide's list, not the script's
existing entries. So the box set the same rule twice with conflicting actions
(nondeterministic last-write-wins; it landed on AuditMode). Verify even counted
'16 total' (one too many logical rules).

FIX: removed the duplicate, kept the single AuditMode entry (the reasoned pentester
choice - Enabled would block the user's own PSExec/WMI tooling). 16 GUIDs, all unique.

NEW GUARD: harness check 'no duplicate ASR rule GUIDs' + asr_dup sabotage, so a
duplicated rule can never ship again. This is the SECOND time a 'thought it was
missing, was already there' mistake happened (also the RestrictSendingNTLM area) -
the lesson: when a coverage-diff grep returns N matches, CHECK whether they are in
the script already vs the guide, do not assume MISS.

37 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.

STILL UNVERIFIED ON HARDWARE: the operational unlock auto-relock (schtasks firing).
That remains the one high-value live test: -Unlock printing -UnlockMinutes 2.


## Password/lockout policy -> opt-in with enforce/relax (36th pass)

User: make the password requirements opt-in under extra security, with an
enforce AND a remove/relax path. Correct instinct - the AccountPolicy module was
in the BASELINE (menu 2), so 14-char/complexity/5-try-lockout was being silently
imposed on LOCAL accounts. On a personal or lab box that is a footgun (can lock you
out of your own accounts).

CHANGES:
- Removed AccountPolicy from the baseline safeModules (added to the -notin
  exclusion list). It no longer runs in menu-2 harden.
- Refactored Invoke-Mod-AccountPolicy to take a -Relax switch:
    ENFORCE (default): capture current 'net accounts' values first (Get-Current
      AccountPolicy, recorded as a ManualStep so the change is documented/undoable),
      then apply the CIS values (14-char, complexity, history, 5-try lockout).
    RELAX (-Relax): apply permissive Windows defaults (minlen 0, maxage unlimited,
      no history, lockout off, complexity off) - the 'remove requirements' path.
- Extra security > 11 'password policy' -> sub-prompt e/r/b (enforce / relax /
  back), each Confirm-Apply gated.
- Updated the -Notes section (item B.12) to document it as opt-in + reversible.

NEW GUARD: harness check 'opt-in modules excluded from baseline' (+ optin_leaked
sabotage) asserts AccountPolicy/DeviceGuard/BitLocker/WDAC/AdminAccount/Outbound
all stay in the baseline-exclusion list, so an opt-in module can't silently drift
back into menu-2 harden.

Note: AccountPolicy stays in the DISPATCH table (so -OnlyModules AccountPolicy
still works, defaulting to enforce) - it's just out of the default plan.

38 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## 4-tier guide RE-REVIEW - confirmed complete, no changes (37th pass)

The 4-Tier Hardening Framework guide was submitted again (same one reviewed in the
26th pass). Rather than re-diff loosely and risk re-adding a duplicate (the ASR-GUID
class of bug), did a COMPLETE control-by-control re-diff of every item in the guide
against the live file, checking BOTH presence AND correct disposition:

ALL 23 adopted controls present and correctly placed:
  baseline: LLMNR, NetBIOS (reg + per-adapter), mDNS, LanmanServer/Workstation,
    RemoteRegistry, RRAS, WinRM, SMBv1 removal, DODownloadMode, SMB signing,
    guest-auth off, RestrictAnonymous, LmCompat=5, RestrictSendingNTLM, RPC
    (=1 not the guide's 2), RDP NLA, IPv6 transition, mobile hotspot, fw logging.
  opt-in: admin shares (AutoShareWks) + UNC hardening via aggressive-network;
    full outbound-deny via -BlockOutbound.

ALL declined items confirmed STILL absent (no leakage), each with its documented
reason: DoHPolicy=3 (fragile - breaks all DNS if DoH unreachable), W32Time hardcoded
NtpServer (env-specific), local-rule-merge-off (needs GPO), adapter-binding strips /
MAC randomization / SMB2-disable (Tier 4 / breaks modern file access).

OUTCOME: nothing to add - the guide is fully covered. Made NO code changes. This is
the correct result; re-adding covered controls would only risk another duplicate.
Verified current state still clean: 38 sabotages, balanced, ASCII, no double-
backslash, ALL PASS. The discipline that mattered: recognizing a re-submitted guide
and confirming coverage rather than reflexively 'adding' to it.


## End-to-end documentation sweep + robustness audit (38th pass)

Full E2E sweep for gaps and doc accuracy (no new features - hardening what exists).

DOC GAPS FOUND + FIXED:
1. 4 params had NO .PARAMETER help (ExtractExcept, Menu, NoMenu, PesterTest) -
   added. Now 41/41 params documented.
2. -Notes UEFI-lock claim was WRONG (bug-26): it said the tool 'deliberately does
   NOT set the UEFI lock', but there IS a -CredentialGuardUEFILock opt-in flag that
   sets it. Corrected the wording to 'off by default, available via the flag, here
   is the lock-in risk'. A doc that contradicts the code is exactly the class we
   hunt.
3. README was badly STALE - written before ~7 major features. Fixed:
   - menu section showed 6 wrong options; now the real 8 (added self-tests, help,
     operational; corrected extra-security contents).
   - added -Notes / -AuditReport / -Unlock / -Relock to invocations.
   - Modules section listed the wrong baseline (missing LockScreenUI, Network
     Services; AccountPolicy now correctly shown as opt-in with enforce/relax).

ROBUSTNESS CHECKS (swept, found SOUND - did NOT 'fix' non-bugs, bug-29/30):
- Every Test-RegInvariant has a matching Set-Reg (no bug-26 verify/setter mismatch).
- Every menu handler + dispatch function defined.
- No dead params (all 41 wired to real behavior).
- Get-LocalUser calls flagged as 'unguarded' are inside Invoke-Step (try/catch) -
  confirmed guarded, left alone.
- Dry-run integrity: raw state-changers are all inside Set-Reg/Invoke-Step (self-
  guard) or in operational-unlock funcs (correctly outside dry-run apply scope).
- All 4 embedded blobs decode + sha256-match disk.

NEW GUARD: 'README baseline list matches source' harness check + readme_drift
sabotage - so the README's documented baseline can't silently drift from the
actual module split again (which is exactly what had happened).

FINAL COHERENCE: 4538 lines, 75 functions, 28 modules, 41/41 params documented,
35 verify checks, 150/151 Set-Reg audit-labeled, 39 sabotages, balanced, ASCII,
no double-backslash, ALL PASS. The bundle (ps1 + 4 embedded tools) is internally
consistent and the docs now match the code.


## Security-controls taxonomy - JSON + generated MD (39th pass)

User asked for a security-controls taxonomy in JSON format, listing whether each
control is closed, its risk rating, and context. Built:
  - security-controls-taxonomy.json (source of truth): 66 controls across 19
    domains, each with coverage (closed/opt_in/partial/not_covered), risk
    (critical/high/medium/low), tier (1-4), module, MITRE ATT&CK domain mapping,
    and context (the why + tradeoff + breakage warning).
  - security-controls-taxonomy.md: GENERATED from the JSON (can't drift), with a
    coverage-summary rollup + per-domain tables.

DERIVED FROM SOURCE not memory: the control list comes from the script's actual
-Item audit labels + module structure + ASR rule array + net-accounts policy, so
the taxonomy reflects what the tool really does.

Coverage rollup: 42 closed / 18 opt-in / 1 partial (WDAC audit-mode) / 5 not-
covered (LAPS/dMSA/UEFI-boot/WDAC-enforce/drift-monitor - each with documented
why). Risk: 4 critical (all closed: WDigest, LSASS-PPL, SMBv1, UAC) / 29 high /
28 medium / 5 low. Carries the standing CIS/STIG-numbers-are-indicative caveat and
honestly marks the schtasks auto-relock as unverified-on-hardware.

Delivered: security-controls-taxonomy.json + .md in outputs.


## Sixth guide review - AI/telemetry eradication (40th pass)

Reviewed a deep AI-telemetry/artifact eradication guide (Recall, Copilot, Click to
Do, Windows AI Fabric, CDP, plus aggressive persistence tactics). Coverage-diff:
already had the core Recall + Copilot kill switches; triaged the rest into 3 buckets.

ADOPTED into Privacy BASELINE (Bucket A - 7 items, each one policy key/service,
reversible, only costs the AI feature):
  - AllowRecallExport=0 (blocks Recall DB export API - exfil path)
  - DisableClickToDo=1 (contextual screen analysis off)
  - Edge HubsSidebarEnabled=0 (Copilot sidebar in Edge off)
  - Notepad DisableAIFeatures=1 (text scraping off)
  - Paint DisableCocreator=1 + DisableGenerativeFill=1 (generative AI off)
  - DisableSearchBoxSuggestions=1 (Start Copilot/Bing suggestions off)
  - WSAIFabricSvc service disabled (spawns WorkloadsSessionHost, 3-5GB RAM; via
    Disable-ServiceSafe so prior StartMode captured; skipped if absent). +verify
    checks for ClickToDo + Edge sidebar.

DECLINED with documented reasons (added to -Notes section A item 9):
  - CDPSvc/CDPUserSvc disable (Bucket B): guide itself calls CDPSvc a kernel
    dependency; killing per-user svc risks BSOD. We already get the cloud-clipboard
    privacy win via AllowCrossDeviceClipboard=0 without that risk.
  - Registry deny-SYSTEM ACLs (Bucket C): sabotages the OS servicing model, can
    BLOCK security patches, near-impossible to cleanly undo. HARD DECLINE - a
    hardening tool must never sabotage updates.
  - IFEO Debugger traps (Bucket C): IFEO is itself MITRE T1546.012 persistence that
    EDR flags as malicious. A defensive tool planting them trips the detection we
    want. HARD DECLINE.
  - Cache PURGE of ukg.db/ActivitiesCache.db/ImageStore (Bucket C): deleting user
    data is destructive + irreversible (no undo). We DISABLE collection (right);
    wiping existing data is a different, riskier op. Documented the paths in Notes
    for the user to do manually + deliberately if they want it.
  - Recall DISM feature-removal: policy-disable is reversible + sufficient; DISM
    removal is heavier and feature-name varies by build. Policy is enough.

This is the RIGHT balance: took the clean privacy wins that fit the no-exfil
posture, declined every tactic that sabotages updates, trips EDR, or destroys data.
The philosophy held: reversible + non-destructive + doesn't fight the OS.

39 sabotages, balanced, ASCII, no double-backslash, PS7-clean, ALL PASS.


## Targeted audit of the AI additions - two real fixes (41st pass)

'Keep on it' - stress-tested the newest (40th-pass) AI code, since new code is where
bugs hide. Found and fixed TWO real things (not padding):

1. DisableAIDataAnalysis was HKLM-only, but the guide specifies HKLM & HKCU. Recall/
   AI analysis runs in USER context (AIXHost etc), so the HKLM-only setting had a
   user-context bypass the guide explicitly warns about. Added the HKCU copy - and
   this matches the both-hives pattern already used for the Copilot kill-switch, so
   it's consistent, not novel. REAL gap closed.

2. The WSAIFabricSvc call I added last pass had a REDUNDANT extra dry-run guard
   (if(-not DryRun){...}else{DRY log}) that no other Disable-ServiceSafe call has.
   Traced the dry-run flow: Invoke-Step skips the actual Set-Service in dry-run, AND
   Add-Undo has its own 'if(DryRun){return}' - so Disable-ServiceSafe is ALREADY
   fully dry-run-safe. My extra guard was harmless but inconsistent with the
   codebase. Simplified it to the standard one-line call + passed Category='Privacy'
   so it groups under the Privacy module correctly (Add-Result Category is a free
   string, confirmed).

VERIFIED-BY-READING (did NOT add a harness check - would be padding): confirmed
Add-Undo guards dry-run with an explicit one-line return, so NetworkServices service
disables never write phantom undo entries in dry-run. Self-evident in source.

Honest note: this pass was worth doing - the newest code had a genuine both-hives
gap. But the tool is at the point where these are refinements, not structural gaps.
39 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## AI-key ACL lock - the deny-SYSTEM tactic, as a gated opt-in (42nd pass)

User decided to INCLUDE the deny-SYSTEM-ACL tactic I'd declined in the 40th pass -
as an explicit lockdown option with a confirmation that shows the risk info. This is
a defensible call: the tactic is legitimate IF the user fully understands the trade.
Built it to be maximally safe FOR a dangerous operation:

Invoke-AILockAcl (extra-security option 12):
  - Denies SYSTEM write on WindowsAI + WindowsCopilot policy keys so a Windows
    Update (running as SYSTEM) cannot re-enable the AI-off settings.
  - BIG RED INFO BLOCK printed on activation: explains it breaks part of the
    servicing model, can make updates fail/leave the box unpatched, may trip EDR,
    and confuses the next admin. Explicitly recommends the SAFER ALTERNATIVE
    (just re-run the tool after updates).
  - STRICTER confirmation than the usual YES: must type the exact phrase
    'LOCK AI KEYS' - can't be a reflexive keypress.
  - REVERSIBLE: records a Command undo that PurgeAccessRules(SYSTEM) + restores
    inheritance, AND prints the manual restore command per key. Also a ManualStep.
  - Dry-run safe (prints WOULD, changes nothing).

Safety invariant LOCKED IN the harness: new check 'AI-key ACL lock keeps confirm+
undo+dryrun safety' (+ ail_unsafe sabotage) asserts the function keeps its strict
phrase, its Add-Undo, its dry-run guard, and a real deny-ACE-removing undo. So this
dangerous option can never silently lose its guardrails in a future edit.

Taxonomy updated: the ACL-lock moves from the declined 'not_covered' bucket to a
gated 'opt_in' (70 controls, 19 opt-in now). The OTHER aggressive tactics (IFEO
traps, cache purge, CDPSvc disable) STAY declined with reasons - only the ACL lock
was requested.

Honest note: I still would not recommend this for most environments (re-running the
tool post-update is safer), and the tool SAYS SO on activation - but it's the user's
box and the option is now theirs to make, fully informed and reversible.
40 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## Close the loop: audit can now SEE the ACL lock (43rd pass)

'Keep on it' - stress-tested the 42nd-pass ACL lock (newest+sharpest code). Found a
real bug-26-adjacent gap: the tool could MAKE the deny-SYSTEM ACL change but could
NOT SEE it. Test-RegInvariant checks registry VALUES; the lock is an ACL on the key,
so Verify/menu-3/the HTML audit report would show NOTHING about it. An auditor running
the read-only audit after a lock would have no indication SYSTEM is denied on the AI
keys - the exact state that can block Windows Update.

FIX: added ACL-lock detection to the Verify module. For each AI key it reads the ACL,
looks for a Deny-write ACE on SYSTEM, and reports:
  - INFO 'SYSTEM is DENIED write ... CAUTION: can block Windows Update ... revert
    before troubleshooting patch failures'  (when locked)
  - INFO 'not locked (normal ...)'  (when not)
INFO (not FAIL) because it's an opt-in the user deliberately chose - but the caution
text makes the patch-blocking risk visible to whoever audits. Flows automatically
into the HTML -AuditReport too (Write-Check -> Add-Result 'Info' -> results table).

This closes the loop the 42nd pass opened: apply option 12 -> menu 3 / -AuditReport
now REPORTS the lock is active + why it matters. A tool that can make a change must
be able to see it (bug-26 discipline).

Verified: Write-Check ValidateSet already includes INFO; status-coherence harness
check still green; INFO path proven by existing Defender-cloud-reporting checks.
40 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## Audited the undo generator (oldest load-bearing code) - sound + 1 test gap (44th pass)

Instead of auditing newest code again, pressure-tested the OLDEST, most load-bearing
code: the undo/rollback generator. If it has a latent bug, every 'reversible' claim
in the tool is false. Reasoned through concrete edge cases:

FINDINGS - the undo generator is SOUND (confirmed, not assumed):
  - Prior-value-ABSENT case: Set-Reg correctly records a RegRemove (not a
    RegRestore with null Value that would wrongly recreate the value as 0/empty).
    This is the subtle edge case I most expected to be wrong; it's right.
  - Un-renderable types (MultiString/Binary): honestly emitted as a MANUAL note,
    not a broken literal command (bug-26 honesty applied to the rollback itself).
  - Quote-escaping: paths/values with ' are doubled safely.
  - The 43rd-pass ACL-lock Command undo: hand-rendered it into the emitted
    try{}catch{} - quotes even, parens/braces/brackets balanced, no bare $ in the
    double-quoted catch string. Valid PowerShell. Reversible as claimed.

TEST GAP CLOSED (real, not padding): the harness MODEL 9 tested render_undo (given
actions), but did NOT test Set-Reg's DECISION of which undo Kind to record. Added
MODEL 9b (test_setreg_undo_kind) pinning the critical property: a value we CREATED
is reversed by REMOVE, a value we CHANGED is reversed by RESTORE, a no-op set
records nothing. With a setreg_absent_restores sabotage (the recreate-as-0 bug).

This was worth doing: it re-confirmed the tool's central 'everything is reversible'
promise holds even for the newest ACL-lock, and closed a genuine gap between what
the code decides and what the harness checks. 41 sabotages, balanced, ASCII, no
double-backslash, drift clean, ALL PASS.


## E2E doc sweep: Item labels + taxonomy + stale README claim (45th pass)

Full end-to-end documentation sweep. Found and fixed FOUR real gaps:

1. THIRTEEN Set-Reg calls had NO -Item audit label (EnableAutoDoh, SMB signing
   client+server, RDP NLA, Remote Assistance, 5x activity/widgets/news privacy,
   HVCI, 2x BitLocker XTS). They applied fine but showed the raw registry path
   instead of a control name in the audit log/CSV/HTML. Added meaningful labels to
   all 13 -> now 100% of Set-Reg calls are audit-labeled. The 2 SMB signing labels
   deliberately match their Verify check names (client/server) for clean traceability.

2. STALE README safety claim (bug-26): README said 'none of this has run on real
   hardware yet' - but it HAS (multiple clean box runs, 2 hardware-found bugs
   fixed). Corrected to an accurate 'what is proven vs not' paragraph: baseline
   proven on hardware, decision logic harness-verified, only the schtasks auto-relock
   still unproven. Second time README drift bit - the drift harness check covers the
   baseline module list but not prose claims, so this was caught by the manual sweep.

3. README missing the AI-key ACL lock (option 12) in the extra-security description
   and safety section. Added it with the danger note + the 'just re-run after
   updates' safer-alternative.

4. TAXONOMY didn't reflect that the ACL lock is now AUDIT-DETECTABLE (43rd pass).
   Updated the ACL-lock entry to note Verify/-AuditReport detect it, and added a
   distinct 'Detection of the AI-key ACL lock' capability under Audit Logging.
   Taxonomy now 71 controls (45 closed / 19 opt-in / 1 partial / 6 not-covered).

ROBUSTNESS re-confirmed (swept, SOUND, no changes): every verify check still has a
setter (36/36), every param documented (41/41), every dispatch module + menu handler
defined, all embedded blobs match, status-coherence green.

4744 lines, 41 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL
PASS. The docs (inline -Item, README, help, Notes, taxonomy) now all match the code.


## WinINET / Internet Settings TLS hardening (46th pass)

User shared a screenshot of Internet Options > Advanced (inetcpl.cpl). Good catch:
that legacy dialog's SECURITY section (below the visible cosmetic items) maps to
WinINET settings that still back system-wide TLS for IE-engine/WinINET HTTP clients
(Edge IE-mode, some .NET and system components). The tool did SCHANNEL protocol
disabling (SSL2/3) but had NO WinINET SecureProtocols coverage - a real gap: the
OS crypto layer was pinned but the WinINET layer could still negotiate old TLS.

ADDED to Network baseline (5 well-documented settings):
  - SecureProtocols = 10240 (0x2800 = TLS 1.2 + 1.3 only; SSL2/3, TLS1.0/1.1 off),
    HKLM + HKCU (user-context clients read HKCU). Verified my bitmask math before
    writing (2048+8192=10240; my first scratch note said 0xA00 which was wrong).
  - CertificateRevocation = 1 (WinINET checks CRL/OCSP) HKLM+HKCU
  - WarnonBadCertRecving = 1 (warn on cert address mismatch)
  - DisableCachingOfSSLPages = 1 (no HTTPS page content lingering on disk)
  + 2 verify checks (SecureProtocols, CertificateRevocation).

DECLINED (discipline held):
  - "Check for signatures on downloaded programs" - the WinTrust 'State' bitmask is
    poorly documented and sources DISAGREE on the value; a wrong crypto-trust
    bitmask could DISABLE checking (opposite of intent) or break installs. Dropped
    it rather than ship a guessed crypto value. 5 solid controls beats 6 with a guess.
  - Enhanced Protected Mode (breaks IE-mode intranet apps), DOM Storage (breaks
    sites), empty-temp-on-close (IE-specific, marginal), and all the VISIBLE cosmetic
    items in the screenshot (text size/zoom/FTP view/underline/smooth scroll).

This is the WinINET PEER to the existing SCHANNEL work - now both the OS crypto
layer AND the WinINET layer are pinned to modern TLS, closing the downgrade path.
Taxonomy: 72 controls. 4750 lines, 41 sabotages, balanced, ASCII, drift clean, ALL PASS.


## Block-all-inbound: the complete "no reachable ports" answer (47th pass)

User: 'I want no inbound ports open, double-check and add blocks.' Analyzed the two
layers this actually requires:

ALREADY DONE (confirmed, not changed):
  - Firewall default inbound = Block (all profiles) + Verify checks it.
  - Listener services silenced: SMB, RDP, WinRM, RPC, SSDP, UPnP, discovery, mDNS,
    LLMNR, NetBIOS.
  - RDP + WinRM firewall groups disabled.

THE REAL GAP: default-inbound=Block does NOT mean no ports open. Windows ships many
ENABLED inbound ALLOW rules (Network Discovery, File/Printer Sharing, Cast to
Device, mDNS, Remote Assistance, Delivery Optimization inbound, AllJoyn) that punch
holes through the default. The tool disabled only RDP/WinRM groups, not the rest.

ADDED - Invoke-Mod-BlockInbound (opt-in: -BlockAllInbound flag / dangerous menu 'i'):
  - Disables EVERY enabled inbound allow rule so the default-block is the only
    inbound policy -> nothing reachable.
  - PRESERVES Core Networking + Core Networking Diagnostics (DHCP, IPv6 neighbor
    discovery, loopback) - dropping these breaks connectivity itself, which is
    beyond 'no inbound ports' and into 'no network'. Documented that tradeoff.
  - NEVER touches outbound rules (would break the box).
  - Remote-session guard: refuses over RDP/WinRM without -Force (disabling inbound
    severs the reconnect) - same discipline as the remote-access module.
  - Fully reversible: records a per-rule Enable-NetFirewallRule undo.
  - Dry-run safe (counts what it WOULD disable).
  + Verify check: reports the count of non-core inbound allow rules, so the exposure
    is visible whether or not you locked it down (INFO, PASS when zero non-core).

Wired as a proper opt-in module: dispatch table, baseline-EXCLUSION (harness opt-in
check confirms), param + help (42/42 documented), dangerous-menu 'i', README module
list, taxonomy (73 controls, 20 opt-in). Sharp option, so it gets Confirm-Apply +
the remote-session stop + reversibility + audit visibility - the full guardrail set.

4855 lines, 41 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## Level 2 lockout-risk tier + RDP/SSH lockdown (48th pass)

User: add a segmented 'lock down network RDP and SSH' option (lockout risk), NOT
mixed with other lockout items, and build a 'Level 2 harden' tier of lockout-capable
items runnable individually OR as a batch. Good architecture request - the sharp
options were scattered; this groups them coherently.

NEW MODULE - Invoke-Mod-RdpSshLockdown (-LockdownRemoteShell, opt-in):
  - Closes BOTH network remote-shell paths together: RDP (service TermService +
    'Remote Desktop' firewall group + fDenyTSConnections=1) and OpenSSH server
    (sshd + ssh-agent + OpenSSH-Server-In-TCP firewall rule).
  - Does NOT touch the SSH CLIENT (outbound, useful) - only the inbound server.
  - Uses Assert-NotSeveringOurAccess: refuses over the RDP/WinRM session it would
    sever, unless -Force. Reversible (per-path undo). Skips SSH cleanly if sshd absent.

NEW TIER - Show-Level2Menu (main menu option 9):
  Groups the lockout-risk lockdowns in one place, each runnable INDIVIDUALLY or as
  a BATCH:
    1 RDP+SSH lockdown | 2 block all inbound | 3 block outbound | 4 NTLM=deny
    a run ALL (batch, each still confirmed + session-guarded)
    e evaluate ALL (dry-run, then resets the flags so nothing stays armed)
  Kept OUT of the safe baseline entirely - nothing lockout-risky runs from menu 2.
  The batch chains the modules but each keeps its own Confirm-Apply + remote-session
  guard, so the batch can't silently sever your access.

WIRING: -LockdownRemoteShell param+help (43/43 documented), RemoteShell in dispatch
+ baseline-exclusion, main-menu option 9, README menu+module list, taxonomy (74
controls, 21 opt-in, + a Level 2 tier description in the doc header).

NEW GUARD: 'Level 2 batch references real opt-in modules' harness check (+
l2_batch_broken sabotage) - asserts every module in the batch exists in dispatch AND
that RemoteShell/BlockInbound are excluded from baseline. So the batch can't ever
reference a phantom module or accidentally pull a lockout item into menu-2.

4973 lines, 42 sabotages, balanced, ASCII, no double-backslash, drift clean, ALL PASS.


## Un-embed the packed files + documentation cleanup (49th pass)

User: move the packed files out of the ps1, and clean up the docs. Confirmed the
intent (un-embed to 5 separate files + tighten docs) before the big refactor.

UN-EMBEDDED (the .ps1 was 14% base64 blobs):
  - Removed the entire EMBEDDED TOOLS region (740 lines of base64 for the 4
    companion files) - they already exist on disk as the source of truth, and the
    embed matched them (verified no drift before removing, so nothing was lost).
  - Removed Invoke-ExtractTools entirely (no longer needed - files ship separately).
  - Rewrote Invoke-PesterTest to run Harden-Windows11.Tests.ps1 from the script's
    own directory instead of a fresh temp extract.
  - Removed the -ExtractTools / -ExtractPath / -ExtractExcept params + help +
    example + menu entry + dispatch (params 43 -> 40).
  - Removed the embed-drift harness check + embed_drift sabotage (meaningless now).
  - Repointed the README-baseline-drift harness check to read README.md from DISK
    instead of the embedded copy (the check still guards README staleness).
  Result: ps1 4990 -> 4140 lines (~850 removed). The .ps1 is still self-contained
  for HARDENING (no runtime deps); only the test files now ship alongside it.

DOC CLEANUP:
  - Stale restore-point label 'Pre-Hardening-v2.1' -> 'v2.2' (a real bug: a v2.2
    tool was stamping v2.1 restore points).
  - Condensed the script header: replaced two long 'WHAT CHANGED' changelog blocks
    (~30 lines duplicating the Notes file) with a tight OVERVIEW + pointer, kept the
    DESIGN section.
  - Fixed stale 'everything embedded / -ExtractTools / temp extract' claims in
    README and run-tests.bat to reflect the separate-files reality.

VERIFIED: balanced, ASCII, no double-backslash, PS7-clean, 40/40 params documented,
every dispatch module + menu handler defined, native -SelfTest static audit clean
(no embed dependency), README-drift check green from disk. 41 sabotages (was 42;
embed_drift correctly removed), 104 harness checks, ALL PASS.

Files now: Harden-Windows11-v2_2.ps1 (4140), 0wintest-logic.py (956),
Harden-Windows11.Tests.ps1 (122), run-tests.bat (24), README.md (214). Keep them
in the same folder.
