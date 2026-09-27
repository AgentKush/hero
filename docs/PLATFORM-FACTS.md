# HERO — Measured platform facts

Everything in this file was **measured on the target machine**, not recalled. Where a design
decision depends on platform behaviour, it must cite a fact from here rather than an assumption.

Machine: Windows 11 Pro build 26200 (x64) · i9-12900K (16C/24T) · 63.8 GB RAM
Toolchain: .NET SDK 10.0.401, WindowsDesktop runtime 10.0.11 · PowerShell 7.6.6 · winget 1.29.290
(SDK and PowerShell re-read 2026-09-25; the line previously said 10.0.303 / 7.6.5.)
Measured unelevated (the default HERO runs in).

---

## 1. Build configuration

`net10.0-windows10.0.26100.0`, `UseWPF=true`, `UseWindowsForms=true`. **Zero NuGet packages.**

Three compile-breaking collisions arise from enabling both UI frameworks. All are solved once
in `Hero.csproj`; do not work around them per-file:

| Collision | Resolution in `Hero.csproj` |
|---|---|
| `Application` ambiguous (`System.Windows` vs `System.Windows.Forms`) | `<Using Remove="System.Windows.Forms" />`, reach WinForms via the `WinForms` alias |
| `Brush`/`Color`/`Font` ambiguous (`System.Windows.Media` vs `System.Drawing`) | `<Using Remove="System.Drawing" />`, reach GDI+ via the `Gdi` alias |
| `Path` ambiguous (`System.IO` vs `System.Windows.Shapes`) | `<Using Remove="System.Windows.Shapes" />` — bare `Path`/`File`/`Directory` then mean `System.IO` as a C# developer expects. XAML still resolves `<Path>` fine, because XAML type resolution is independent of C# usings. |

`WFO0003` (a WinForms analyzer demanding DPI be configured via `Application.SetHighDpiMode`) is
suppressed: that advice is WinForms-specific, WPF requires the manifest declaration, and WinForms
is present here only for `NotifyIcon`.

**WPF cannot be trimmed** — XAML resolves types by reflection at runtime, so `PublishTrimmed`
must stay `false`.

## 2. In-box vs NuGet — verified by reflection probe

| Assembly | Status | Consequence |
|---|---|---|
| `Microsoft.Win32.Registry` | **in-box** | Persistence enumeration needs no package |
| `System.Text.Json` | **in-box** | Baseline/state persistence |
| `System.Diagnostics.PerformanceCounter` | **in-box** | CPU/memory sampling |
| `System.Drawing.Common` | **in-box** (via WindowsDesktop) | Dynamic tray icon rendering |
| `System.Windows.Forms.NotifyIcon` | **in-box** | Tray support |
| `System.Management` (WMI) | **MISSING** | No WMI. Use registry + P/Invoke + targeted shell-outs |
| `System.ServiceProcess.ServiceController` | **MISSING** | Services come from `HKLM\SYSTEM\CurrentControlSet\Services` |

## 3. Telemetry cost — measured, not estimated

| Operation | Result | Note |
|---|---|---|
| `ProcessProbe.Snapshot()` | **358 processes in 21ms** | Toolhelp32 + per-process open |
| Command line via PEB read | **221–254 of ~358, in 9–21ms** | The 100+ failures are higher-integrity processes |
| Command line via WMI (`Get-CimInstance Win32_Process`) | **3095ms** | ~340× slower. Rejected outright. |
| `NetworkProbe.Snapshot()` | **143 sockets in 4ms** | TCP4/6 + UDP4/6 with owning PID |
| Signature verify, cold | **61 unique images in 1350ms** (~22ms each) | Far too slow for the poll loop |
| Signature verify, warm cache | **1ms** | Cache key = path + size + last-write-time |

**Consequence:** a 1-second poll of processes + sockets costs ~25ms of one core (~0.1% of this
CPU). Signature verification must never run on the poll thread — only on first sight of an
unknown image, on a background worker, with results cached.

## 4. Authenticode: the catalog trap

`notepad.exe` and `powershell.exe` have **no embedded signature**. They are catalog-signed via
`Microsoft-Windows-*.cat`. `X509Certificate.CreateFromSignedFile` throws
`CryptographicException: Cannot find the requested object` on them.

Verification **must** be: `WinVerifyTrust(WTD_CHOICE_FILE)` → on `TRUST_E_NOSIGNATURE` only,
fall back to `CryptCATAdmin*` catalog lookup → `WinVerifyTrust(WTD_CHOICE_CATALOG)`.
11 of 61 running images on this machine are catalog-signed. Skipping the fallback would report
Windows itself as unsigned.

A **present-but-invalid** signature must never fall through to the catalog path — that state
(tampered/revoked/untrusted root) is strictly worse than unsigned and must be preserved.

Revocation checking is disabled (`WTD_REVOCATION_CHECK_NONE`): it performs CRL/OCSP network I/O,
which would stall scanning and leak the machine's software inventory to third parties.

## 5. The false-positive evidence that shapes the whole detection design

A scan of live processes found **9 unsigned running images. Every single one is benign:**

```
C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime_...\WidgetService.exe   <- Microsoft's own
C:\Users\finla\AppData\Local\Microsoft\WinGet\Packages\astral-sh.uv_...\uv.exe
C:\Users\finla\AppData\Local\Microsoft\WinGet\Packages\astral-sh.uv_...\uvx.exe
C:\Users\finla\AppData\Local\uv\cache\archive-v0\...\Scripts\python.exe
C:\Users\finla\AppData\Local\uv\cache\archive-v0\...\Scripts\browser-use.exe
C:\Users\finla\AppData\Roaming\Claude\Claude Extensions\...\.venv\Scripts\windows-mcp.exe
C:\Users\finla\AppData\Roaming\Claude\Claude Extensions\...\.venv\Scripts\blender-mcp.exe
C:\Users\finla\AppData\Local\Packages\Claude_...\uv\python\cpython-3.12.12-...\python.exe
```

These are unsigned **and** running from `%LOCALAPPDATA%` / `%APPDATA%` — i.e. they satisfy the
two conditions most naive rules combine ("unsigned" + "user-writable directory"). Several also
make outbound network connections.

**Therefore, as a hard design rule:** unsigned-ness is a *weak* score contribution and can never
by itself justify an action. High-confidence (auto-act) verdicts require multiple independent,
corroborating signals — e.g. unsigned **and** newly-created **and** freshly-persisted **and**
beaconing to a rare external endpoint. Python venv shims, `uv` caches and language toolchains
must be recognised as a normal developer software class, not as anomalies.

## 6. Unelevated blind spots — state these honestly in the UI

| Capability | Unelevated result |
|---|---|
| Process enumeration (pid/ppid/name) | **All 358** |
| Image path + integrity level | **226 of 358** (132 blind, 37%) |
| Command lines | **221 of 358** |
| Per-PID socket table | **Full** — all 143 rows |
| `HKCU`/`HKLM` Run, Winlogon, IFEO, Services (841 keys) | **Full read** |
| Scheduled tasks (`schtasks /query`) | **Full read — 299 tasks** |
| Killing SYSTEM/protected processes, firewall rules, DISM | **Requires elevation** |

Integrity distribution observed: Medium=174, Unknown=132, Untrusted=34, Low=15, High=3.
`Untrusted=34` is normal (sandboxed/AppContainer content processes), **not** a threat signal.

HERO ships `asInvoker` — a tray app that triggers UAC every boot teaches the user to click
through prompts, which is a net security loss. Elevation is requested on demand, per action.

## 7. Socket-table gotchas

- Ports are stored as a DWORD with the port in **network byte order in the low two bytes**.
  Decode as `((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)`. Getting this wrong yields port 20480
  for 80. Verified correct: observed ports 443 and 5228, none > 65535.
- `TIME_WAIT` rows are commonly owned by **PID 0**. These are not a process and must be excluded
  from per-process attribution rather than attributed to a phantom.
- Loopback and RFC1918 peers dominate a developer machine. Beaconing analysis must consider
  only genuinely external peers (`Connection.IsExternal`).

## 8. Measured runtime cost of HERO itself

A guardian has no right to be a resource hog. Measured on this machine:

| State | CPU | Working set | Handles |
|---|---|---|---|
| Tray-resident, hidden (normal operation) | **1.60% of one core = 0.067% of 24 threads** | 105 MB | 545 |
| Dashboard open, live projection every second | 5.4% of one core | 232 MB | 2448 |

Stability over 60s: handles −4, working set flat, thread count flat. No leak.

Two design consequences:

1. **The window skips its projection while hidden.** Rebuilding WPF visuals for nobody cost
   ~3% of a core. The engine keeps observing; only the render is suppressed, and a flag
   triggers a repaint on re-show.
2. **Signature verification never runs on the poll thread.** At ~22ms per unseen image it
   would blow the one-second budget on its own. New images are queued to a serialised
   background worker so a burst of process starts cannot cause a thundering herd.

### The architecture bug this measurement caught

An earlier revision owned the `MonitorEngine` on `MainWindow` and started it from `Loaded`.
Idle CPU measured a beautiful 0.003% — because `Loaded` never fires for a window that is never
shown, so launching with `--tray` (exactly how HERO starts at logon) **never began monitoring
at all**. A defence system that only defends while you are looking at it.

The engine therefore lives in `GuardianService`, a singleton started from `App.OnStartup`,
and the window is only a view onto it. Suspiciously good performance numbers are a symptom
worth investigating, not a result worth celebrating.

## 9. Event log: what is actually reachable unelevated

`System.Diagnostics.EventLog` (including `EventLogWatcher` and `EventLogQuery`) **is in-box**, but
only under `Microsoft.WindowsDesktop.App`. A plain console app cannot see it: the types are
type-forwarded and the implementation assembly is not referenced. HERO references WindowsDesktop,
so it has them; test harnesses must set `UseWindowsForms` to reproduce.

**Push-based monitoring works unelevated — verified.** A live `EventLogWatcher` subscription
received an event during testing.

| Channel | Unelevated | Note |
|---|---|---|
| `System` 7045 / 7040 | **Readable** | Service installed / start type changed |
| `Microsoft-Windows-Windows Defender/Operational` 1116/1117/5001/5007 | **Readable** | Detections, config changes |
| `Microsoft-Windows-PowerShell/Operational` 4104 | **Readable** | Script-block logging |
| `Security` 4688 (process creation) | **DENIED** | `UnauthorizedAccessException`. Polling is mandatory, not optional |
| `Microsoft-Windows-TaskScheduler/Operational` | Readable but **`IsEnabled = False`** | Disabled by default. A silent channel is not a clean one — check `EventLogConfiguration.IsEnabled` and report it as unavailable |

## 10. Defender as HERO's malware oracle

`MpCmdRun.exe -Scan -ScanType 3 -File <path>` works **unelevated**. Verified against the standard
EICAR test string: reported `found 1 threats`, remediated, exit code 0.

This is HERO's reputation source, in preference to any cloud API: free, unlimited, no API key, no
account, signatures refreshed several times daily (measured 0 days old), and **no data leaves the
machine**. Sending hashes to a third party would leak an inventory of installed software for worse
intelligence.

Two caveats that must be respected in code:

1. **It is not a read-only query.** Defender acts on what it finds under the machine's policy.
   Callers must treat a `Threat` verdict as "the file may no longer exist".
2. **It fails while another scan is running** (`already in progress`, `hr = 0x8050111c`). Observed
   repeatedly. Treat as a normal outcome, not an error.

Defender's Operational log also serves as a free local threat database describing what has actually
happened on this machine.

## 11. Antivirus blocks more than reads

When Defender considers a file malicious it refuses **every** handle to it, not just read access.
`File.Move` fails with `ERROR_VIRUS_INFECTED (0x800700E1)`. Verified against a real detection here.

So HERO cannot quarantine a file that AV is already blocking — **and does not need to**. The correct
behaviour is to detect the HRESULT, report "already contained by antivirus", and defer. Fighting the
AV that already won is pointless. `QuarantineVault` implements exactly this.

## 12. Single instance, hide-to-tray and elevation handover

Three bugs here compounded into "it restarts and dies", and they are worth keeping written down
because each looks harmless alone.

1. **A hidden window is not a closed window, and a closed window is not null.**
   `Window.Show()` on a CLOSED window throws
   `Cannot set Visibility or call Show ... after a Window has closed`, and `_shell ??= new(...)`
   does not save you because the field is still non-null — it points at a destroyed window. The
   fix is to clear the reference in `Closed`, and to cancel `Closing` so Alt+F4, the taskbar
   Close and the system menu hide the window instead of destroying it. Only the title-bar button
   went through the hide path before.

2. **A second launch must surface the running instance, not exit silently.**
   With the window hidden in the tray and the single-instance mutex held, launching HERO did
   nothing whatsoever and there was no way back to the window. A named `EventWaitHandle` that the
   running instance waits on, and a second launch sets, fixes it.

3. **An elevated copy cannot take over while the mutex is held.**
   `SelfElevate` started the elevated copy, that copy hit the single-instance guard and exited
   instantly, and the outgoing instance then shut itself down — leaving nothing running. The
   elevated copy is now launched with `--replace` and waits up to 20s for the mutex.

   **`Mutex.WaitOne` THROWS `AbandonedMutexException` when the previous owner died without
   releasing** — which is precisely the crash case where replacement matters most. That exception
   means ownership WAS acquired; treating it as a failure made handover impossible after a crash.
   Verified both paths: killed original and graceful exit.

## 13. Environment notes

- **~~Git Bash is broken on this machine~~ — FIXED 2026-09-25.** The cause was Mandatory ASLR,
  not Git. Full diagnosis, the measurements behind it, the reversal and the residual gotchas are
  in **§39**; this entry stays as the pointer, because the original note sent readers to
  PowerShell for months.

- **Windows PowerShell 5.1 and PowerShell 7 resolve execution policy from different stores, and
  it is not two registry keys.** Measured 2026-09-25. 5.1's key
  `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell` holds **no
  `ExecutionPolicy` value at all** (`GetValueNames()` returns only `Path`), so 5.1 falls back to
  `Undefined` -> Restricted and refused a local, unsigned, MOTW-free `.ps1`:
  *"running scripts is disabled on this system"*, exit 1. pwsh 7 (7.6.6, the MSIX/Store build)
  ran the identical file, exit 0, and reports `RemoteSigned` from
  `$PSHOME\powershell.config.json` (`{"Microsoft.PowerShell:ExecutionPolicy": "RemoteSigned"}`).
  `HKLM\SOFTWARE\Microsoft\PowerShellCore` does not exist here -- an earlier version of this
  bullet sent readers looking for it. What was **not** measured, so do not rely on it: whether an
  MSIX build is *unable* to write HKLM. PS7 does still consult
  `HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore` for group policy; that key is absent on this
  machine, so the path was never exercised.
  The consequence is the point: a script that "should run" per one shell is blocked in the other.
  Use `powershell -NoProfile -ExecutionPolicy Bypass -File ...`, which is per-process and stores
  nothing.
- `dotnet new sln` produces **`.slnx`** (XML) on SDK 10, not `.sln`.
- The build creates transient `Hero_<hash>_wpftmp.csproj` projects; errors are reported against
  those names. This is normal WPF behaviour, not a project misconfiguration.

## 14. Self-protection: what a certificate-less app can and cannot have

Measured 2026-09-03. Every number below is from this machine, not from documentation.

**The wall.** Defender's engine cannot be killed, by design:

```
sc qprotection WinDefend  =>  PROTECTION LEVEL: ANTIMALWARE LIGHT
Stop-Process MsMpEng      =>  DENIED: Access is denied.
```

That is Protected Process Light. Reaching it requires a binary signed with a Microsoft-issued
anti-malware certificate plus an ELAM driver, both gated behind Microsoft Virus Initiative
membership; a kernel driver stripping `PROCESS_TERMINATE` via `ObRegisterCallbacks` is behind the
same gate plus attestation signing. **Neither is available to this project.** Do not design as if
they were, and do not tell a user HERO is unkillable.

Machine state relevant to that judgement: VBS running (`VirtualizationBasedSecurityStatus` 2),
HVCI **not** running (`SecurityServicesRunning` 0), `%ProgramFiles%` correctly refuses unelevated
writes (`UnauthorizedAccessException`).

**What was actually achieved instead.** HERO installed to `C:\Program Files\HERO` with the
guardian registered as the `HeroGuardian` LocalSystem service. Verified from an unelevated shell:

| Attack | Result |
| --- | --- |
| `Stop-Service HeroGuardian` | DENIED — `Cannot open 'HeroGuardian' service` |
| `Stop-Process` the service pid | DENIED — `Access is denied` |
| Append to `C:\Program Files\HERO\HERO.exe` | DENIED — `UnauthorizedAccessException` |
| Modify `C:\ProgramData\HERO\integrity.json` | DENIED — `UnauthorizedAccessException` |
| Delete that manifest | DENIED |

Write access to the install directory is held only by `BUILTIN\Administrators`,
`NT AUTHORITY\SYSTEM` and `NT SERVICE\TrustedInstaller`. The signed-in user is not on that list.

**The one call that makes the restart real.** `SERVICE_CONFIG_FAILURE_ACTIONS` alone is decorative:
the SCM treats a `TerminateProcess`'d service as an ordinary stop, not a failure, so recovery
actions never fire. `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG` with
`fFailureActionsOnNonCrashFailures = TRUE` is what converts "died without saying it was stopping"
into a failure. Configured as three restarts (1s / 5s / 15s, 86400s reset) and confirmed present
via `sc qfailure`. **The end-to-end kill-and-restart test has NOT been run** — it needs elevation
and the prompt was declined. Treat restart-after-privileged-kill as configured-but-unproven until
someone runs it.

**Service DACL**, set explicitly rather than left to the SCM default (which varies by creation
path and can include looser ACEs for Authenticated Users). Confirmed with `sc sdshow`:

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
```

Interactive users get query and interrogate only — no `RP` (start), no `WP` (stop), no `DC`
(change config). Administrators deliberately keep full control including `SD`: a service its own
machine's administrator cannot remove is behaving like malware, and they can take ownership
anyway, so locking them out would be theatre.

**Service state must move.** `HeroPaths` resolves `LocalApplicationData`, which for LocalSystem is
`C:\Windows\System32\config\systemprofile\AppData\Local\HERO` — a different directory from the
signed-in user's. This is why the service does **not** yet host the guardian engine: two engines
would write two baselines and two hash-chained ledgers, and a hash chain with two writers is not a
hash chain. State moves to `%ProgramData%\HERO` when the UI moves onto an IPC pipe.

**No in-box `ServiceBase`.** `System.ServiceProcess.dll` in the shared framework is a 15 KB
type-forwarding facade; `GetTypes()` returns 0 and the real implementation ships only in a NuGet
package. With the zero-package rule, the service is hosted by P/Invoking
`StartServiceCtrlDispatcherW` / `RegisterServiceCtrlHandlerExW` / `SetServiceStatus` directly.
Both SCM callback delegates must be rooted in static fields or the callback lands in freed memory.

**`StartupRegistration.Reconcile` was dead code** — written, documented as running on every start
to heal a moved executable, and called by nothing. Now invoked from `GuardianService.Start` on a
background thread. Confirmed working: starting the Program Files copy rewrote the `HKCU\...\Run`
value from the old `bin\Debug` path to `"C:\Program Files\HERO\HERO.exe" --tray` unprompted.

**Self-recognition must cover every artefact HERO creates.** The moment the service shipped, HERO
reported `HeroGuardian` on its own Threats page — LOW, score 8.6, "Unsigned program starts
automatically" — with buttons offering to remove the auto-start or quarantine the target file.
`IsOwnStartupArtifact` covered Run keys, scheduled tasks and Startup shortcuts, because those were
the only artefacts that existed when it was written. The rule this establishes: **adding a new way
for HERO to persist means adding the matching arm to `IsOwnStartupArtifact` in the same change**,
or the product ships a self-destruct button.

Self-recognition for the service anchors on two things, in order: the running executable's path,
then the install directory recorded in the integrity manifest. The second matters because a
service registration is machine-wide and outlives any one build — a developer running `bin\Debug`
against an installed service is the ordinary case, and matching only the running path would raise
a false impersonation signal on the author's own machine. The filter lives in the scoring loop
only, so the service still appears on the Persistence screen: a tool that erases itself from its
own inventory is doing what malware does.

## 15. State move to %ProgramData% and the guardian IPC

Measured 2026-09-03.

**Why the move.** A LocalSystem service's `LocalApplicationData` is
`C:\Windows\System32\config\systemprofile\AppData\Local` — a different directory from the signed-in
user's. `%ProgramData%` is the one root both identities resolve to identically. Migration copies
rather than moves and stamps the old root with `moved-to-programdata.txt`; the original is left in
place so a bad move is recoverable. Result on this machine: 17 files copied, 1 skipped (already
present), learned baseline and hash-chained ledger preserved.

**The ACL trap, in the order it actually bit.** Three measured states, each one a fix for the last:

1. Service migrated first → every state file owned by SYSTEM → `settings.json`, `baseline.json`
   and `events\ledger.jsonl` all **DENIED** to the signed-in user. The app is still the writer, so
   it would have failed to save anything, silently.
2. Granted `BUILTIN\Users` Modify on the state directory → app writes work, but the ACE inherits,
   so `integrity.json` went from DENIED to **WRITABLE**. A tamper manifest that the tampering can
   rewrite is not evidence.
3. Service-owned files (`integrity.json`, `service.log`) now carry their own protected ACL —
   inheritance off, SYSTEM and Administrators full, Users **read only**. Final measured state:
   app state writable, evidence denied but still readable.

**Protect once per process, not on file creation.** The first attempt gated the log's ACL fix on
"did this call create the file". It failed on the ordinary upgrade path: during a reinstall the
OLD service was still running, recreated `service.log` itself, and the new build then saw an
existing file and never protected it. Verified broken, then fixed with a per-process flag.

**This user-write grant is transitional and it weakens the state directory.** It exists only
because the guardian still runs inside the tray app. When the guardian moves into the service and
becomes the sole writer, the grant is removed and the directory tightens to SYSTEM and
Administrators. Until then, a process running as the user could edit the baseline — which is
exactly why the ledger is hash-chained.

**IPC.** Newline-delimited JSON over `\\.\pipe\HERO.guardian.v1`. `System.IO.Pipes.AccessControl`
is a facade (0 types, 7 forwarded) but `NamedPipeServerStreamAcl.Create` resolves at runtime, so
no package is needed. Pipe DACL: LocalSystem and Administrators full; **Interactive** read/write;
nobody else. Interactive rather than Authenticated Users is deliberate — a service account a
compromised application runs under must not be able to interrogate the guardian, and a remote
caller over `\\host\pipe\` carries the Network SID, so remote access is excluded by the same rule
rather than a separate check that could be forgotten.

Verified against a raw PowerShell client: `ping` and `integrity` return correct data, an unknown
operation returns `{"ok":false,"error":"Unknown operation ..."}`, malformed JSON returns
`{"ok":false,"error":"Request was not valid JSON."}`, and the service survives both.

**Still outstanding:** the guardian itself has not moved. The service hosts integrity watching and
the IPC endpoint; the tray app still owns the engine, and the 9 pages still read it in-process.
Porting those pages is what makes the detection itself unkillable.

## 16. The command surface, and what testing it found

Measured 2026-09-03, from an UNELEVATED client against the LocalSystem service.

**The rule.** Every command names its target by subject key; the service resolves that key against
verdicts it currently holds and acts on the `Subject` found there. It never accepts a path, a pid
or a registry location from the caller. HERO is now LocalSystem with a pipe any interactive user
can open — a command surface taking arbitrary targets would be a general-purpose "terminate any
process, quarantine any file, delete any registry value as SYSTEM" service. Verified:

| Attempt | Result |
| --- | --- |
| `act killTree` / `quarantine` / `removePersistence` on an invented subject | REFUSED — no such finding |
| `act` with `path` instead of `subjectKey` | REFUSED — `'subjectKey' is required` |
| `act` with `pid` instead of `subjectKey` | REFUSED — `'subjectKey' is required` |
| `allow` / `recheck` an invented subject | REFUSED |
| `settings.raw` with a non-allowlisted key | REFUSED — `'autonomy' is not a settable preference` |

Two deliberate exceptions: `dismiss` needs no live verdict (it changes only HERO's notification
state and refusing would make the button unreliable exactly when pressed), and `undo` names a
ledger action id the engine validates itself.

**A test that did damage, and the flaw it exposed.** Round-tripping settings.json through
`settings.save` was supposed to be a read-back check. The service, as written, adopted the incoming
object wholesale, so it saved what came back: `ObservationEndsUtc` null — **ending the shakedown
period that gates autonomous action** — `RunAtStartup` true to false, and `FirstRunUtc` reset to
now. Any interactive process could have done that deliberately.

`ReplaceSettings` now MERGES user preferences only. `ObservationEndsUtc`,
`AutoActionDisabledUntilUtc`, `FirstRunUtc`, `LastStartUtc`, `LastCleanExitUtc`, `SchemaVersion`
and the allowlists stay as the service holds them. The allowlists matter as much as the dates:
`Scorer.Allow` enforces narrow scopes when an entry is added through the allow command, and
accepting a wholesale list here would be a way around it. Re-verified with a hostile payload that
set `maxAutoActionsPerHour` 5→9, nulled the observation window and injected
`allowedImages: [C:\evil.exe]` — the preference applied, the window held at 2026-09-05, first-run
held at 2026-09-02, and the allowlist stayed empty.

**Do not repair settings.json through PowerShell's JSON round-trip.** The first repair attempt used
`ConvertFrom-Json` / `ConvertTo-Json`, which re-rendered dates and the `quietHours` TimeSpans in
formats `HeroSettings.Load()` could not parse. Load fell back to defaults and `SaveSafe` wrote
those over the file, losing more than the original test had. Text edits preserve the exact formats
the application writes.

**Mixed casing on the wire.** `JsonTypeInfo.CreateJsonPropertyInfo` takes the property name
verbatim — the naming policy is NOT applied to properties added by a resolver modifier. The pipe
therefore carried camelCase for public properties and PascalCase for every internal one. It
round-tripped perfectly, because both halves share the resolver, and was invisible until a
hand-written camelCase payload silently deserialised to all-defaults. Diagnosed by an error naming
`$.Autonomy` — PascalCase had matched. The policy is now applied by hand, and
`JsonStringEnumConverter` is registered so enums travel as names rather than ordinals whose meaning
shifts if a value is ever inserted mid-enum.

**Still outstanding:** the state directory has not been tightened to SYSTEM-only. The UI no longer
writes settings or the vault, but it still writes `logs\motion.log` and `logs\ipc.log`, so the
grant cannot simply be removed — the diagnostics need a per-user home first. And the ~420 KB-per-
second state poll remains unmeasured.

## 17. What the state poll actually costs

Measured 2026-09-03 on this machine (24 logical cores), 45s sampling windows, service installed to
Program Files with one dashboard attached.

**First attempt returned a lie.** `Process.TotalProcessorTime` reported the service at exactly 0
CPU in both phases. That is not a measurement, it is a permission: an unelevated caller cannot read
processor time for a LocalSystem process, and the API returns zero rather than failing. A silently
zero number is worse than an error. Performance counters are readable by the Users group and were
used instead.

**CPU, by difference (service alone vs service with one client polling):**

| | mean % of one core | peak | % of this machine |
| --- | --- | --- | --- |
| Service, nobody polling | 2.14 | 7.77 | 0.09 |
| Service, one client polling | 3.63 | 6.23 | 0.15 |
| **Service cost of the poll** | **1.49** | | |
| Dashboard (parse + apply) | 1.59 | 18.71 | 0.07 |
| **Combined** | **3.08** | | **0.128** |

0.128% of a 24-core machine is cheap. Scale it honestly before calling it free: the same 3.08% of
one core is ~0.77% of a 4-core laptop, and the dashboard's peak sample was 18.71% of a core.

**Payload and latency**, 25 consecutive calls:

- 500,240 bytes mean (min 499,731 / max 500,813) — **489 KB/s sustained at 1 Hz**
- round trip 17.7 ms mean, 11.6 ms best, 30.4 ms worst

**Memory**: the dashboard sawtooths between 88 MB and 117 MB private over 90s, handle count flat
(+0), threads stable. That is the garbage collector working, not a leak — but the amplitude is the
allocation churn of half a megabyte of JSON per second.

**Composition — where the 500 KB goes:**

| Section | bytes | share |
| --- | --- | --- |
| snapshot.processes (338) | 212,672 | 42.9% |
| persistence (426) | 120,496 | 24.3% |
| recentStarts | 73,088 | 14.8% |
| signatures | 47,852 | 9.7% |
| snapshot.connections (137) | 17,057 | 3.4% |
| connectionVerdicts | 16,161 | 3.3% |

**About half of every poll is data that did not change.** Persistence is a quarter of the payload
and is rescanned every TEN MINUTES — it is re-sent 600 times per change. `recentStarts` is process
records already present in `processes`. Signatures change only when a new image is verified.
Gating those three on a change token would cut roughly 48% of the traffic and most of the
allocation churn, and none of it is difficult: the poll is a pull, so the client can send the
version it last saw and the service can answer "unchanged".

Not done, because it is an optimisation to a cost that is currently affordable, and the measurement
had to come first.

### Change-gating the poll — what it did and did not buy

Implemented after §17. The persistence inventory and the recent-starts list are now sent only when
their version counter differs from the one the client reports holding. Measured over 60 polls of a
live machine:

- persistence re-sent **0 / 60**, recent starts re-sent **1 / 60** (a process genuinely started)
- payload **489 KB/s → 295 KB/s**, a **39.7% reduction**, matching the prediction
- **CPU did not move: 3.08% → 3.04% of one core, within noise**

That last line is the point worth keeping. Cutting 40% of the bytes bought no measurable CPU,
because the cost was never in the bytes that were removed — it is in the process array, which is
now **72%** of what remains, plus the fixed per-poll work of building the signature table and
assessing every connection. An optimisation aimed at payload size was measured against payload
size and succeeded; had it been sold as a CPU optimisation it would have been a failure, and only
measuring both revealed which it was.

Remaining composition of the 302 KB steady-state poll: processes 72.0% (343 items), signatures
15.7%, connections 5.4%, connectionVerdicts 5.1%. Anything further has to attack the process array
— either by gating it the same way (it changes every second, so gating buys nothing) or by sending
only what changed since the last snapshot, which is a real diff protocol and a much larger piece of
work.

**Correctness check that mattered:** null means "unchanged, keep what you have", never "empty". The
Persistence page renders 427 entries that were transmitted once and then not sent again for 50
seconds of polling. That is why the fields are nullable rather than defaulting to empty lists —
an empty list would blank the page every second, and the type makes that mistake hard to write.

## 18. Maintenance: dead code, a dishonest headline, and a 2,741x measurement trap

**DevCaches was never called.** `DevCaches.cs` is 823 lines covering uv, npm, pip, cargo, Gradle,
Maven, NuGet, pnpm, Yarn, the JVM and VS Code, its own header records 14 GB measured on this
machine, and `DevCaches.Enumerate()` was invoked from nowhere in the product. Neither were
`FindBuildOutputs`, `FindVirtualDisks`, `FindOrphanedNodeModules` or `FindUnrealProjects`.
`DiskCleanup.Enumerate()` is the single path the Maintenance page reads: a catalogue not added
there does not exist as far as the user is concerned. Now wired in — uv 6.5 GB (224,647 files) and
npm 1.9 GB (171,544 files) appear on the page.

**The headline counted space it refuses to free.** It summed every measured row, including the
read-only observations that exist so HERO can explain why it will NOT touch them. Measured: it
read "203.4 GB reclaimable" when 177.2 GB of that was virtual machine disks, WinSxS and the
installer caches. Now split: "26.2 GB reclaimable across 22 places. A further 177.2 GB is measured
but never cleaned."

**Sparse files over-report by three orders of magnitude.** Verified on this machine:

```
%LocalAppData%\Google\Play Games\...\userdata.img
    logical 512.0 GB    on disk 191.2 MB    ratio 2,741x
```

on a volume with ~200 GB free. `FileWalk` reads logical length by design — allocated size costs an
extra syscall per file, which is the difference between a 13-second walk of 1.5M files and minutes
— and takes the true size per-item on preview lists only. That trade is sound, but it means ANY
target whose tree contains a sparse file reports a fantasy total. Sampled VHD/VHDX files on this
machine are NOT sparse (logical == on-disk), so the existing 145.3 GB virtual-disk row is honest;
the Play Games image is excluded from every target. Any new target under a directory that can
contain a disk image must exclude images explicitly rather than trusting the sum.

### The adversarial safety review, and what it caught

Three reviewers, one per new file, briefed to find a way the code destroys user data. All three
returned NEEDS_FIX: one catastrophic, six serious. Every one was fixed or the row was dropped
before anything was deployed.

**Catastrophic — `browser.firefox.site-data`.** Rooted at `profile\storage\default` with no filter.
On Gecko that directory holds WebExtension storage under `moz-extension+++<uuid>` — for a password
manager or wallet extension, an encrypted vault whose only copy is that directory. The Chromium
sibling row excludes extension state explicitly, with a comment that a content blocker's filter
list "has no server copy at all"; the identical data on Gecko was deleted with no mention in the
Description or in WhatBreaksIfWrong.

Its stated safety guarantee was also false. The Description said data a site "explicitly asked to
have kept permanently is left alone", justified by excluding `storage\permanent` — but on modern
Firefox an origin granted `navigator.storage.persist()` lives in `storage\default` with a flag in
`.metadata-v2`. The exclusion bought nothing and the sentence told the user the opposite of what
happened. **Row dropped.**

**Serious — `browser.firefox.session-backups`.** Claimed `sessionstore.jsonlz4` is the live copy.
After a crash the sole record of the open tabs is `sessionstore-backups\recovery.jsonlz4`, and the
`firefox.exe` blocker cannot fire because after a crash the process is gone. It reassured the user
at the one moment the reassurance was wrong. **Row dropped.**

**Serious — the credential row was one token from a shredder.** `browser.chromium.credentials` is
safe as written (NeverClean forces ReadOnly and the executor aborts), but it collects its paths
through a helper that deliberately skips the name guard, and `ProtectedPaths.IsForbidden` does not
know `Login Data`, `Web Data`, `Bookmarks`, `key4.db` or `logins.json`. Changing NeverClean to High
would have turned it into a working password and bookmark shredder with its Paths already aimed at
every credential store.

Fixed with `ProtectedPaths.IsNeverDeletableName`, checked at the single per-file choke point in the
executor. Deliberately NOT `BrowserProfileNames`, which is the wider tripwire for cache targets:
that list names Cookies, Local Storage and IndexedDB, which the privacy rows exist to delete on
purpose. The new list is only the subset that is never a legitimate deletion in any row.

**Confirmed defect — `logs.windows-debug` would have deleted a system directory.** It omitted
`PruneEmptyDirectories = false`. Both matching `.log` files live in `C:\Windows\debug\WIA`, not at
the root, so clearing them empties it; WIA is not a declared root and is not on the ProtectedPaths
floor, so the pruner walks up and removes the directory. It is created at install time with an ACL
granting the imaging service write access, which is not reconstructed — scanner tracing would
silently stop. The author had written the exact argument against this on the sibling row and not
applied it here.

**Two Automatic tiers withdrawn.** `shell.widgets-web-cache` deleted without asking from inside a
live Chromium profile whose `Default` directory holds Login Data, Web Data and History right now —
safe as written, wrong shape, and its comment claimed the board "has effectively never been used"
when Cache measures 244 files / 22.46 MB. `app.electron.discovered` chose its paths at runtime from
every AppData child with a `GPUCache` or `Code Cache` child, intersected with an allowlist
containing the generic name "Cache" — a path set no reviewer can enumerate is the wrong thing to
delete from unattended. Both now Prompt.

**Latent double-claim.** `logs.modern-setup`'s root sits inside `logs.event-trace`'s root and was
not in its `ExcludeSubPaths`, so any `.etl` appearing there would be measured by both rows — and a
row that reads 0 B after the user ran the other one reads as a broken tool. Excluded.

Final state: 74 targets, 49 with reclaimable space, 33.6 GB genuinely reclaimable and 179.3 GB
measured-but-refused, deployed to Program Files with the service hardening re-verified.

## 19. Duplicate detection: hardlinks and the cost of identity

Measured 2026-09-03, independently of the agents that are building the feature, so their claims can
be checked against a number rather than against their own report.

**WinSxS is 100% hardlinked.** Sampled 4,000 files under `C:\Windows\WinSxS` and read
`NumberOfLinks` via `GetFileInformationByHandle`:

```
hardlinked (NumberOfLinks > 1) : 4000
single-link                    : 0
unreadable                     : 0
bytes in the sample            : 1,995.9 MB
```

Not "mostly", as `DiskCleanup.cs:866` puts it — every single sampled file. Against the 21.9 GB
WinSxS total the Maintenance page reports, a duplicate finder that ignores link identity would present
essentially that whole tree as reclaimable and free **zero bytes**. That is the single failure that
would make the feature worse than not shipping it, because the user acts on the number.

**Identity costs 36x a metadata walk.** Same 6,000-file sample:

| | files/s |
| --- | --- |
| Metadata already in hand from enumeration | 654,622 |
| Plus one `CreateFile` + `GetFileInformationByHandle` per file | 17,966 |

0.056 ms per file — **83 seconds of identity lookups alone** on a 1.5M-file volume, before a single
byte is hashed. So identity cannot be applied during the walk. It belongs after same-size grouping,
on candidates only, which is a small fraction of any real tree.

**Identity does NOT hydrate cloud files.** The handle above is opened with `FILE_READ_ATTRIBUTES`
(0x80) and `FILE_FLAG_BACKUP_SEMANTICS`, requesting no read access at all. That matters because
`ScannedFile.IsCloudPlaceholder` exists to keep hashers away from dehydrated OneDrive files, and it
would be easy to assume the same restriction applies to identity. It does not: link identity is
safe to take on a placeholder, only the CONTENT read is not.

**Re-verified after challenge.** An adversarial reviewer of DuplicateFinder.cs reported this figure
as false — 3,019 links>1 against 981 links==1, i.e. 75.5% rather than 100%. Re-measured three ways
before accepting or rejecting that:

| sample | links > 1 | links == 1 | unreadable |
| --- | --- | --- | --- |
| first 4,000 in enumeration order | 4,000 | 0 | 0 |
| random 4,000 of 119,075 | 4,000 | 0 | 0 |
| random 12,000 of 119,075 | 12,000 | 0 | 0 |

The original figure stands. The reviewer's own supporting number explains the likely confusion: it
reported 3,920 DISTINCT IDENTITIES among its 4,000 files and appears to have read that as evidence
against hardlinking. It is not. Most WinSxS entries are distinct physical files whose additional
links point OUTWARD into System32, so a near-unique identity count and a 100% multi-link rate are
the same observation, not contradictory ones. Recorded because a confident, well-argued and wrong
correction is worth more to the next reader than a silently re-run number.

## 20. The dashboard froze the moment the guardian moved out of process

Reported as "this still checking seems to be stuck": the posture line sat at
`Still checking signatures: 265 of 344 distinct images verified` and never moved.

It was not stuck. Nothing was stuck. Navigating to another page and back resolved it instantly to
`10 unsigned images are running`, which is the completed state.

`MainWindow.OnGuardianObserved` is the ONLY thing that calls `RefreshCurrent()`, and it is wired to
`GuardianService.Observed`. That event is raised in exactly one place — the local poll loop in
`MonitorEngine.RunAsync`. When the guardian moved into the LocalSystem service that loop stopped
running in the UI process, and `ApplyRemote` — which publishes the snapshot, verdicts, persistence,
signatures and peer verdicts on every one-second poll — never raised it.

So since the service move, **every page rendered once when navigated to and never updated again**.
Not the signature counter: the whole dashboard. Process lists, connection tables, the score ring.
The tray app was a screenshot of the moment you opened it.

`MonitorEngine.AcceptRemote` was `Latest = snapshot` and nothing else. It now diffs against the
previous snapshot and returns a `SnapshotDelta`, and `ApplyRemote` raises `Observed` with it after
every section is published — last, so a page refreshing in response sees a consistent view rather
than a half-applied one.

### Why it read as a stalled scan rather than a frozen UI

The text it froze on was progress text. A frozen "265 of 344" is indistinguishable from a scan that
has stopped advancing, so the symptom pointed at the verifier and the IPC — neither of which had
anything wrong. Querying the service directly over its own pipe is what settled it:

```
processes  : 362
signatures : 358
distinct running images the service has NO signature for: 0
```

The service had answered everything. Only the client was not listening. When a UI shows progress,
a frozen refresh and a stalled worker look identical — so measure the producer before the worker.

### Two real defects found underneath it

Both were genuine, and neither would have completed the counter on its own.

1. **`SignatureVerifier.Verify` never cached a failure.** `!fi.Exists` and the stat `catch` both
   returned `Unreadable` without writing to `_cache`, and an unrecorded answer is indistinguishable
   from no answer: `TryGetCached` kept saying null and the path was re-requested forever. Negative
   results are now cached path-keyed (they have no length or write time to key on) with a 5-minute
   retry, so an image mid-write is not branded unreadable for the life of the process.

2. **The posture line said "distinct images" while counting processes.** ~350 processes run off
   ~107 binaries here, with dozens of svchost.exe instances sharing one file, so the denominator
   was inflated several-fold and "N unsigned images are running" counted one file once per process
   using it. Both figures are now over distinct paths.

Also: nothing ever asked the service to verify process images. It verifies persistence entries, its
own start-up snapshot, and whatever the Network page requests for connection owners. Anything
started later, holding no connection and absent from persistence, was counted and never looked at.
`OverviewPage` now calls `RequestVerification` for the paths it is about to count, the same call
`Pages.cs` already made for the Network table.

## 21. Closing %ProgramData%\HERO to the signed-in user

The state root granted `BUILTIN\Users: Modify`, inherited, because the app used to be the writer.
That has been false since the guardian moved into the service — the only thing still writing there
as the user was diagnostics: motion.log, ipc.log, app.log.

Measured on this machine BEFORE the change, as the unelevated signed-in user. Eleven operations
succeeded:

```
create file  in \, \logs, \events, \undo, \vault      ALLOWED
append       baseline.json, settings.json,
             dismissed.json, events\ledger.jsonl      ALLOWED
rewrite DACL baseline.json                            ALLOWED
rename       dismissed.json                           ALLOWED
```

The ledger is hash-chained precisely so that editing it is detectable. It was also freely
appendable, so that a UI animation counter had somewhere to write.

### Three things are required, and doing only the obvious one leaves it open

Each was measured, not reasoned about.

**1. Inheritance must be broken.** `C:\ProgramData` itself carries `BUILTIN\Users: Write
(ContainerInherit)` and an inherit-only `CREATOR OWNER: GENERIC_ALL`. Removing HERO's own explicit
Users ACE leaves both flowing down and the user can still create files.

**2. Existing files must be rewritten, not just the directory.** That `CREATOR OWNER` ACE stamps an
EXPLICIT full-control entry for the creating user onto each file the app made, and `File.Move`
carries the descriptor along when a `.tmp` is renamed over the target. Measured: `baseline.json`
carried an explicit ACE for the signed-in user, and an unelevated process could rewrite that file's
DACL — i.e. grant itself back whatever a directory-level lockdown had taken away. The same probe
was DENIED on settings.json, dismissed.json and ledger.jsonl, which had no such ACE. That contrast
is the whole finding: a directory-only lockdown is cosmetic wherever the stamped ACE exists.

**3. Ownership must be reset.** An owner holds WRITE_DAC implicitly, so a file the user owns is a
file the user controls regardless of its ACEs. `logs\ipc.log` was owned by the signed-in user.

Ownership is set to `BUILTIN\Administrators` rather than SYSTEM deliberately: a member of that group
may set it without holding SeRestorePrivilege, so the installer does not need to enable a privilege
to do it.

### Result

Rehearsed against a throwaway copy of the real state directory first — the hazards above were
recreated on it deliberately, the real `HeroPaths.LockDownStateDirectory` was invoked against it by
reflection, and the same unelevated probe was re-run:

```
writable/controllable surface remaining for an unelevated user: 0   (was 11)
readable by the user:                                           6/6 (unchanged)
```

Read access is kept on purpose. The record is about the user and their machine; they may read every
byte of it and change none.

### The configuration this creates, and the one it would have broken

`App.OnStartup` pings the service and falls back to an in-process guardian when it does not answer,
deliberately — "the dashboard must not require administrator rights to be useful". That fallback
is fine on a machine where HERO was never installed, because nothing locked the directory there.

It is NOT fine in the case the lockdown newly creates: installed, so the directory is closed, but
the service stopped or crashed. The in-process guardian would then watch attentively and record
nothing, because every write in the guardian is wrapped in a catch that swallows — a directory this
process cannot write looks exactly like one where nothing needed writing.

So `HeroPaths.CanPersistState()` asks the filesystem directly (create a probe file, delete it) and
the app sets `GuardianService.PersistenceBlocked`. The engine still runs, because live process,
connection and persistence views are read from the machine and remain accurate. The posture line
replaces its reassurance with the truth:

> **Watching, but not recording** — the guardian service is not running, so nothing seen in this
> session is being written to the timeline, the baseline or the vault.

`GrantInteractiveWriteAccess` was deleted rather than left unused: both halves of its premise are
now false, and its only remaining effect would be to undo the lockdown.

## 22. What the adversarial review found in §21 — including two regressions it introduced

An eight-agent review of the lockdown. It found real defects in work that had already been
measured and shipped, which is the point of running one.

### The lockdown made quarantined malware MORE available, not less

The worst finding, and mine. Measured on the live vault after §21 shipped:

```
20260902-...-quarantined   Allow BUILTIN\Users  ReadAndExecute (inherited)
                           (no Deny ACE at all)
READ ALLOWED - 18 bytes
```

Two halves, both from the same commit:

1. The sweep stripped **every** explicit rule, and a Deny is a `FileSystemAccessRule` like any
   other. `QuarantineVault.DenyExecute` stamps `Deny Everyone: ExecuteFile` on each payload; the
   sweep removed it.
2. The root's `Users: ReadAndExecute` — added so a person could read their own evidence — then
   inherited onto the payload, granting `FILE_READ_DATA` **and** `FILE_EXECUTE` on quarantined
   malware to every local account. The payload is XOR-masked, which the vault documents as
   obfuscation and not encryption, so the ACL was the only thing holding it.

Quarantining a file had become a way to make it readable and runnable by any user on the machine.

Fixed with `HeroPaths.ProtectQuarantinedPayload`: protected DACL, SYSTEM and Administrators only,
no Users entry at all, Deny-execute retained. Applied at quarantine time and re-applied by the
lockdown sweep. Verified: reading the payload is denied, reading its ACL is denied, and the
manifest beside it — original path, hash, reason, the part actually worth reading — stays readable.
The Quarantine page still lists the item, because it lists manifests.

"The user may read every byte of their own evidence" is a good rule for the record. It is not a
rule about the sample.

### The "keep already-protected entries" exemption was attacker-plantable

The sweep skipped entries whose DACL was already protected, reasoning that `integrity.json` and
`service.log` are deliberately stricter. But the test was a property of the file, not a statement
about which file it is — and until the lockdown first runs, the root inherits `%ProgramData%`'s
ACL, which lets any user create files there. So:

```
icacls "%ProgramData%\HERO\baseline.json" /inheritance:r /grant %USERNAME%:(F)
```

on a pre-created file, and the sweep would preserve that grant forever — reintroducing precisely
the stamped-ACE defect §21 exists to remove. Now everything is stripped unconditionally and the
genuinely-stricter files are re-protected afterwards **by name**. Deterministic beats deferential.

### The migration marker orphaned legacy state

`MigrateFromLegacy` counted "destination already exists" and "the copy was denied" in one
`skipped` variable, then wrote the marker regardless — and the marker is a permanent early-out
whose text reads *"no longer read... safe to remove by hand"*.

After the lockdown, every `File.Copy` from the unelevated dashboard is denied. A machine upgrading
would have had its learned baseline and hash-chained ledger orphaned in `%LOCALAPPDATA%\HERO`,
with a note inviting the user to delete the only remaining copy. Separated into `alreadyPresent`
and `failed`; the marker is written only when `failed == 0`, and a failure is logged rather than
swallowed.

Worth knowing and not yet solved: `LegacyRoot` resolves **per token**. The service's is
`C:\Windows\System32\config\systemprofile\AppData\Local\HERO`, which does not exist, so the
service returns before doing anything. The only identity that can see the user's legacy state is
the one the lockdown just stopped from writing the destination.

### Two ungated writes that the lockdown turned from wrong into silent

- `GuardianService.DisposeAsync` called `Baseline?.Save()` with no `IsRemote` guard. When remote,
  `Baseline` is the empty placeholder built in `StartRemote`, and its empty `FilePath` resolves to
  `HeroPaths.Baseline` — so **every clean exit of the dashboard wrote a blank model over the
  service's learned baseline**. `Save()` has no empty-guard. Survivable only because the service
  re-saved from its own in-memory copy shortly after. A live data-loss bug, not an ACL one.
- `MainWindow.OnZoomKeys` called `HeroSettings.SaveSafe()` directly, bypassing the guardian. After
  the lockdown that write is denied and swallowed, so Ctrl+= would silently stop persisting. Routed
  through `GuardianService.SaveSettings` — with a 400 ms debounce, because that route is a blocking
  pipe call and this is a key-repeat handler.

### The ACL was never the boundary: the pipe is

The sharpest finding. `%ProgramData%\HERO` can be closed perfectly and it buys less than it looks,
because the LocalSystem service exposes file primitives over a pipe the Interactive SID may open:

- `Undo(actionId)` → `Path.Combine(HeroPaths.UndoDir, actionId + ".json")`. **`Path.Combine`
  discards its earlier arguments the moment a later one is rooted**, so `actionId =
  C:\Users\me\forged` reads an attacker-authored file — and an `UndoRecord` picks its own effect:
  an arbitrary HKLM value, an arbitrary SYSTEM scheduled task, or a file move out of the vault.
  The comment above the call claimed "the engine validates the id against its own ledger". It did
  not.
- `vault.delete(id)` → the same escape, ending at `File.Delete` as SYSTEM on any `.json` or
  `.quarantined` on the machine — including `integrity.json`, the manifest whose whole purpose is
  to be untamperable. A DACL does not help when SYSTEM is doing the deleting on request.
- `dismiss` took an unbounded `days`. `days = 100000` is a permanent suppression, written by
  SYSTEM into the locked directory, by an unelevated caller — and subject keys are predictable, so
  a finding can be silenced before the thing it would report exists.

All three fixed: `HeroPaths.IsSafeStateId` (whitelist of `[A-Za-z0-9_-]`, single segment, checked
at each use site) and `Math.Clamp(days, 1, 90)`.

**The lesson worth keeping:** a file ACL protects a file from a process. It does nothing about a
privileged process that will act on the file when asked. After hardening a directory, the next
question is not "is it locked" but "who can ask SYSTEM to touch it, and what do they have to prove
first".

### Still open

- `settings.save` lets any interactive caller lower `Autonomy` to Observe, disarming HERO
  persistently. The field allowlist is good; the caller is unauthenticated beyond holding the
  Interactive SID. Requires client-token inspection to fix properly.
- The service binary is installed from wherever HERO is run, and `Elevation.InstallDirectoryIsUserWritable`
  already knows how to detect a user-writable directory but is not consulted at service install.
  A SYSTEM service whose own image the user can rewrite outranks every finding above.
- `IsOwnState` is a bare prefix test with no separator check, so `%LOCALAPPDATA%\HEROIC\` matches.
  It is consulted by five detection sites, which makes any such folder a place HERO promises never
  to flag.

## 23. Closing the three holes section 22 left open

### The service binary outranked everything else

A LocalSystem service is only as trustworthy as the file Windows runs. `ServiceControl.Install`
checked `File.Exists` and nothing else, so registering HERO from a build-output folder pointed a
SYSTEM service at a directory the signed-in user owns — and every permission section 21 tightened
becomes decoration next to "the attacker can replace the binary".

`Elevation.DirectoryWritableByNonAdministrators` decides this, and it reads the DACL rather than
attempting a write. That distinction is the whole finding: `InstallDirectoryIsUserWritable` answers
"can THIS PROCESS write here" by trying it, and at `--install-service` time the process is elevated,
so the probe succeeds in `%ProgramFiles%` and would report the safest directory on the machine as
user-writable. Measured:

```
C:\Program Files\HERO                     unsafe=False
C:\Windows\System32                       unsafe=False
D:\...\bin\Release\net10.0-windows...     unsafe=True   owned by DESKTOP-...\finla
D:\My projects\hero\dist                  unsafe=True   owned by DESKTOP-...\finla
```

Ownership counts as write access: an owner holds WRITE_DAC implicitly and can grant itself the rest.
Inherit-only entries are skipped, or a `CREATOR OWNER` ACE would flag almost every directory on
Windows. Trusted principals are SYSTEM, Administrators and TrustedInstaller — the last has no
`WellKnownSidType` and owns `%ProgramFiles%` on a stock install, so omitting it would fail the one
directory the check exists to approve.

Refused, not warned, with `--allow-unsafe-install-dir` as an explicit escape that records the reason
in the integrity manifest. A warning printed to a log by a windowless elevated child is not a
decision anyone makes. The refusal costs nothing legitimate because the supported install copies
HERO into `%ProgramFiles%` first and registers it from there — verified, exit code 0 from
`C:\Program Files\HERO` and exit code 2 from the build output, with the running service untouched.

Not solved: ancestors above the immediate parent are not walked, so a user who can rename a
grandparent can still swap the directory out. Left as a stated gap rather than a papered-over one.

### The pipe now knows who is calling

Section 22 established that the ACL was never the boundary. The concrete instance:
`settings.save` let any interactive caller set `Autonomy` to `Observe`, which puts the response
engine in permanent dry run. The field allowlist was good; the caller was unauthenticated beyond
being logged in.

`GuardianPipeServer` now impersonates the client once per connection and threads
`callerElevated` down to `ReplaceSettings`. Under UAC a filtered administrator token carries the
Administrators group as DENY-ONLY, so `IsInRole` returns false for an administrator who has not
elevated — exactly the distinction wanted.

**The part that did not work first time, and is easy to get wrong:** `pipe.RunAsClient` requires the
CLIENT to have granted impersonation, and `NamedPipeClientStream` defaults to
`TokenImpersonationLevel.None`. Measured before fixing: an *elevated* client was refused, because
the service could not impersonate anyone and the check failed closed on every caller. `GuardianClient`
now connects with `TokenImpersonationLevel.Impersonation`. Granting it costs nothing — the server is
LocalSystem and already strictly more privileged — and a hostile client withholding it only makes
itself look unprivileged, which denies it the guarded operations rather than granting them.

Guarded in BOTH directions, because there are two ways to hurt someone through these settings:

- **Disarm**: Autonomy to Observe, caps to zero, quiet hours suppressing action. HERO watches and
  never intervenes.
- **Over-arm**: `RequireHardIndicatorForAutoAction` off, caps raised. HERO acts on weaker evidence,
  and can be steered into quarantining the user's own work.

`UiScale`, `RunAtStartup` and `StartupMethod` stay ungated. None affects the guardian — the service
is Automatic and starts without the tray app — and putting the zoom level behind a UAC prompt would
teach people to elevate HERO by reflex, which is worse for them than this is good.

Measured, all four cases:

```
unelevated + Autonomy      -> refused, autonomy unchanged on disk
unelevated + UiScale       -> accepted
elevated   + Autonomy      -> accepted, autonomy changed
UI click, unelevated       -> notice shown, radio reverts to the real level
```

That last row matters as much as the other three. The Settings page previously fired and forgot,
ignoring the reply — so a refusal would have left the radio showing a level HERO was not at, which
is the silent UI/engine disagreement the page's own comment calls out as trust-destroying.

While testing it: the autonomy radios had **no accessible name at all**. Their `Content` is a
`StackPanel` so title and explanation can be styled separately, and WPF surfaces no automation name
for non-string content — a UI Automation walk found four radios each named `""`. A screen reader
announced "radio button" and nothing else for the control that decides whether HERO may defend the
machine. Same defect and same fix as `HeroButton`.

### A folder name was an exemption

`IsOwnState` was `full.StartsWith(Root) || full.StartsWith(LegacyRoot)` with no separator check, so
`%LOCALAPPDATA%\HEROIC\`, `%LOCALAPPDATA%\HEROx\` and `%ProgramData%\HERO-evil\` all counted as
HERO's own. Eight call sites consult it; seven are detection. Together they say HERO will never
accuse a process from there, never score an autostart pointing there, never learn about it, never
list it in recent starts, never firewall it and never quarantine it.

That was survivable while `LegacyRoot` was a legacy directory that might not exist. Putting
`UserLogDir` under it (section 21) made it a normal, always-created, user-writable part of the
product — and therefore the best hiding place on the machine, claimable by choosing a folder name.

Now segment-aware, and split by what the answer is FOR:

- `IsOwnState` — `Root` only. The seven detection sites. Narrow, because promising never to
  investigate somewhere is a serious promise and should only cover a directory nothing but SYSTEM
  can write.
- `IsOwnStateOrDiagnostics` — `Root` + `LegacyRoot`. Exactly one caller,
  `CleanupTarget.IsForbidden`. Refusing to DELETE HERO's own logs is the own-goal the original was
  written to prevent, and that argument does still apply to everything HERO writes.

```
C:\ProgramData\HERO\baseline.json              IsOwnState=True   OrDiagnostics=True
C:\ProgramData\HERO-evil\x.exe                 IsOwnState=False  OrDiagnostics=False
%LOCALAPPDATA%\HERO\logs\svchost.exe           IsOwnState=False  OrDiagnostics=True
%LOCALAPPDATA%\HEROIC\x.exe                    IsOwnState=False  OrDiagnostics=False
```

Row three is the point: a binary planted in HERO's own diagnostics folder is now detectable, while
the cleaner still will not delete the logs.

## 24. The review of section 23: the gate was half a fix

Eight agents over the three changes. The gate itself held — no way was found to make
`ClientIsElevatedAdministrator` return true from an unelevated token, and `ReplaceSettings` has one
caller that always passes it. The finding was that **`settings.save` was the only command gated, and
it is not the most powerful weakening primitive on the pipe.**

Every one of these reached the same end state — the attacker's malware runs unopposed — and most
reached it faster and more durably than setting `Autonomy = Observe`:

| Command | What it gave an unelevated caller |
|---|---|
| `allow` | A 365-day, hash-pinned allowlist entry for their own binary. `ReplaceSettings` excludes allowlists from the settings merge for exactly this reason — "an attacker could simply post an allowlist naming their own binary" — and this command accepted one entry at a time with no check. |
| `dismiss` | Up to 90 days of suppression for a subject that does not exist yet. `Raise()` returns on `IsDismissed` **before** `Respond()`, so a dismissal kills detection and response, not just the notification. Subject keys are built from values the caller chooses (`persist:Category|Location|Name`) or already knows (`proc:<pid>:<start ticks>` for a process it started suspended). |
| `act`/`undo` | Replays an `UndoRecord` as SYSTEM, restoring the registry value, scheduled task or firewall rule HERO just removed. Ids are not secret: the state root grants Users read, so `undo\` can simply be listed. |
| `act`/`resume` | Thaws a suspended process. Its "undoing containment is never gated" comment was written when the only caller was in-process. |
| `vault.restore` / `vault.delete` | Reverses containment, or destroys the evidence. Payloads are closed to Users, but the manifests beside them are deliberately readable — and a manifest's filename **is** the id. |

All now require an elevated caller, except two deliberate carve-outs:

- `allow` with `RuleForEntity` stays open. It silences one rule for one entity, pins no hash, and
  grants no path standing trust — the "stop flagging this for that reason" button.
- `dismiss` is capped rather than gated: an unelevated dismissal is clamped to one day, so the
  "stop telling me about this" button keeps working without becoming a persistence primitive.

**Reversing containment is not the innocent direction.** It was treated as one throughout, because
for an in-process caller it was the user undoing their own click. The move to a service made "the
user" mean "anyone signed in", and every "always allowed" comment written before that move needs
re-reading in that light.

### The cost, stated plainly

An unelevated dashboard can no longer restore or delete from the vault, undo an action, or resume a
suspended process. That is a real reduction in what HERO can do without administrator rights, and it
sits against the stated principle that the dashboard must not require them to be useful. The
judgement was that containment an attacker can trivially reverse is not containment. Every refusal
says what to do, and the Quarantine page already renders the message.

### Two regressions the review caught in section 23's own changes

**Narrowing `IsOwnState` let HERO quarantine its own legacy state.** The vault's refusal floor used
the narrow check after the split, so the legacy baseline, the legacy ledger and the live diagnostic
logs under `%LOCALAPPDATA%\HERO` all became quarantinable — moved into the vault and XOR-masked.
The per-site judgement was wrong for exactly the sites that ACT on a file rather than accuse a
process: `QuarantineVault` and `ProtectedSet`'s file overload now use the wide check, while the
process overload keeps the narrow one. Detection may look in a user-writable folder; containment may
not eat what it finds there. The vault's two floor tests also compared an un-canonicalised path, so
`...\HERO\..\..\Windows\System32\x` reached neither branch; both now canonicalise first.

**A refused settings change poisoned the page.** `_settings` is one object shared by every control,
and the hard-indicator toggle and actions-per-hour box ignored the reply. A refused change stayed in
the model and was carried by the next save, and the next — so one refused toggle would go on to
refuse the deliberately-ungated zoom slider for the rest of the session. Every guarded control now
goes through `SaveGuarded`, which reverts both the model and the control and shows one notice.

### Still open

- The install refusal is log-only. Exit code 2 is correct and the reason is in `service.log`, but
  nothing surfaces it to a person running an installer that does not check. It fails safe — no
  service is registered — so this is an observability defect, not a hole.
- `DirectoryWritableByNonAdministrators` examines the directory, not the file the SCM actually
  executes, and not ancestors above it. A junction above the install path is not considered.
- Nothing re-examines the directory a already-running service was installed from.
- `Manifest.InstallDirectoryUnsafe` is written and never read.
- `MaxServerInstances` is 4, so four held connections deny the pipe to everyone — including the
  administrator who is now the only one who can change anything.

## 25. The dashboard worked only while HERO had nothing to report

Reported as "this page has died or the entire program has not sure": every page blank, the score
ring stuck on its initial zero.

Nothing had died. Both processes were alive and responding, the service answered `ping` in 199
bytes and `state` in 510 KB from an idle prompt, and the Maintenance page — which reads the
filesystem directly rather than the guardian — was updating normally. What had stopped was the
dashboard applying any state at all: no `first state applied` line for that process, ever.

Calling the app's own client by reflection separated the two halves in one shot:

```
PingAsync  -> OK
StateAsync -> NULL after 106ms
```

106ms is not a timeout. It is a parse that threw:

```
NotSupportedException: Deserialization of interface or abstract types is not supported.
Type 'Hero.Guardian.Subject'.
```

`StateReply.Verdicts` carries `Verdict`, whose `Subject` is an abstract record with two derived
types. System.Text.Json will neither write nor read that without being told how, and it had been
told nothing — so subjects went out as `"subject":{}` and came back as an exception.

**The blast radius is the whole reply.** Verdicts is one property of StateReply, so one unreadable
subject meant no snapshot: no processes, no connections, no persistence, no signatures. Every page
blank at once, which is why it read as a crash.

### Why it had never been seen

The guardian holds no verdicts on a quiet machine, and `Verdicts` serialises as `[]` — which
round-trips perfectly. The bug is invisible until HERO raises its first finding, and then it takes
the entire dashboard down in the same second. On this machine the trigger was genuine and correct
detection:

> `evade.service-start-type` — The start type of the Claude service was changed from auto start to
> disabled.

**A security tool that works only while it has nothing to report is worse than no tool, because
the blank screen reads as "all clear".** This is the same failure mode as section 20 — a dashboard
that had stopped listening looked like a machine with nothing happening — arriving by a completely
different route, and it is worth assuming there are others.

Fixed with `[JsonPolymorphic]` + `[JsonDerivedType]` on `Subject`, discriminator written as `kind`
rather than the default `$type` because the wire shape gets read by hand often enough for that to
matter. Verified: subjects now serialise as
`{"kind":"persistence","entry":{...}}`, `first state applied: processes=389` returns, and the
Threats page renders the finding with its subject intact.

### Found on the way

`GuardianClient` used ONE two-second deadline for connect, the service assembling ~540 KB of
state, and the read. That was not the cause here, but it is wrong: it conflates "is anything
listening" with "has it finished answering", and the reply budget is the one that suffers when
the machine is busy — which is exactly when HERO is most worth watching. Connect keeps its two
seconds; the reply now gets twenty.

## 26. Maintenance: one click, honest badges, and the rights HERO already had

### The admin rows were never a rights problem

Six targets read "needs admin" and could not even be MEASURED — about 11.5 GB of Windows Update
download cache, setup logs, Delivery Optimization, font cache and crash dumps. The instinct is to
run the dashboard elevated. The premise is wrong: **HERO already holds more than administrator
rights, permanently.** The guardian service is LocalSystem and has been since boot. The maintenance
half simply ran entirely in the dashboard and never asked it.

Elevating the dashboard would have been worse in every direction — a UAC prompt on every launch, an
always-on high-integrity UI process as permanent attack surface, and a contradiction of HERO's own
rule that the dashboard must not need administrator rights to be useful — to save asking a service
that is already running.

So `MaintenanceHost` runs cleanup targets inside the service. The rule it obeys is the one the
guardian commands already follow, restated for a different noun: **a request names a target by ID,
resolved against the service's own catalogue; a path never crosses the pipe.** There is no request
shape that can express "delete this directory". Verified:

```
maintenance.measure wu.download-cache      -> found, 11,228,492,946 bytes, 734,915 files, Measured
maintenance.measure "C:\Windows\System32"  -> found:false
maintenance.clean   "../../etc"            -> "No such cleanup target."
```

Cleaning is asynchronous — it returns a job id and the client polls — because a target can hold
734,915 files and holding one of the four pipe instances for the minutes that takes would deny the
pipe to everything else, including the guardian's own state polling.

One carve-out: targets whose category is `Logs` or `Diagnostics` still require an elevated caller.
Everything else here is destructive-to-caches, which is irritating to lose and no use to an
attacker; crash dumps and setup logs are the machine's account of itself, and letting an unelevated
process ask SYSTEM to erase them would be an anti-forensics primitive opened in the course of
freeing disk space.

Result: `Measured all 75.` with no qualifier, zero "needs admin" cells, and the 10.5 GB Windows
Update cache visible and cleanable for the first time.

### One-click clean

`AutomationTier.Automatic` was already the right set and did not need inventing — `EffectiveTier`
enforces it centrally, forcing NeedsAdmin to Prompt and NeverClean to ReadOnly, so the button
cannot be widened by a careless declaration in a target file. 22 of 75 targets qualify.

It names every target and the total before deleting anything, and goes through the same
`Preview` → `CleanupExecutor.Execute` pair as the per-row button. There is deliberately no second
delete path: a bulk cleaner that grew its own loop is where a protected-path check quietly goes
missing.

Note what it does NOT include: the 10.5 GB Windows Update cache is `NeedsAdmin`, so it is Prompt,
so it stays out of the one-click set and keeps its own confirmation. "Safe" means no decision
needed, not "big".

### Two honesty fixes

**Empty rows no longer carry a risk badge.** Four Recycle Bin rows all measured "nothing" and all
four displayed HIGH. Emptying a recycle bin genuinely is high risk — it is the user's own deleted
files with no second undo — but an empty one holds nothing to be wrong about, and four red badges
over four empty rows trains the eye to skip the column exactly where it matters. `AccessDenied`
keeps its declared risk: "there is nothing here" is not something HERO knows about a directory it
could not read.

**The clean shows what it is doing.** Deleting the 171,544-file npm cache behind one unchanging
line of text was reported as "stuck on the removal process", which is a fair reading of a screen
that said the same eleven words for four minutes. `CleanupOutcome` now carries `CurrentPath` and
`FilesPlanned`, the executor already reported every 512 files, and the page shows a real bar plus
the file being removed. This is the same "looks identical to a page that has hung" failure the
measuring phase was fixed for, arriving one phase later — worth assuming it will arrive again
somewhere else.

### The button promised space it could not free

Shipped, clicked, and it removed nothing: *"Done. Removed 0 files, 0 B reclaimed from 0 places.
8 left alone: uv package cache: process-running; Opera GX cache: process-running; Steam store and
library cache: process-running"* — while still offering to "Clean 10.9 GB from 15 safe places".

`EffectiveTier == Automatic` answers "may this be cleaned without a decision". It does not answer
"can this be cleaned right now", and on a working machine those are very different questions.
Measured:

```
total in the eligible set : 10.73 GB
blocked right now         : 10.49 GB    uv 6.74, Opera GX 1.49, Steam 0.99,
                                        Spotify 0.41, Discord 0.35, Edge 0.23,
                                        NuGet 0.23, Chrome 0.05
actually cleanable now    :  0.24 GB
```

HERO refuses to delete a cache under a live process, and it is right to — "deleting underneath it
either fails or is silently undone as the app recreates the files". The defect was counting that
space in the offer.

This is the same mistake the page headline had already been fixed for, and the note explaining that
fix was three screens further down this same file: *a cleaner that inflates its own headline with
space it will not free is doing the thing this product exists not to do.* The button had to learn
it separately, which is an argument for making such rules assertions rather than comments.

The blocker probe now runs once after measuring (it enumerates processes, so not per render), the
button counts only what is clear, and what is held is named by the application the user would have
to close:

> **Clean 425.5 MB from 7 safe places**
> A further 10.5 GB across 8 places are in use right now — uv package cache, Opera GX cache, Steam
> store and library cache, Spotify interface cache, Discord cache and others. Close those and the
> figure above will grow.

Blockers are re-probed after every run, because an application may have started or stopped while it
was going.

## 27. Blockers that were wrong about the machine in front of them

Asked to clear the 10.46 GB Windows Update download cache, HERO refused with three reasons. It was
right to refuse — but two of the three were wrong, and finding out which took measuring rather than
reading.

### "A servicing operation is waiting for a reboot" — half true

`PendingReboot()` collected five registry indicators into one flat list and set `Pending` if any
were present. Two very different situations were being treated as one:

- **CBS** `RebootPending` / `RebootInProgress` / `PackagesPending` — component servicing is
  mid-transaction. Files are staged and the restart will consume them; deleting the payload store
  now can genuinely strand it.
- **Windows Update** `RebootRequired` — the install already FINISHED and is waiting for a restart
  to take effect. The payloads in `SoftwareDistribution\Download` are spent.

Measured on this machine while it held the cache:

```
CBS RebootPending            False
WU  RebootRequired           True
TrustedInstaller             Stopped
wuauserv                     Stopped
```

Nothing was in flight. `PendingRebootStatus` now carries `ServicingInFlight`, set only by the CBS
keys. CBS mid-transaction stays a hard block; WU-only becomes an advisory the user may override,
which is what this target's own description already implied — *"clearing this is the standard remedy
for repeated update install failures, which this machine is currently experiencing"*.

### "The cache was written to 94 minutes ago" — measuring the wrong thing

The `download-active` check read `Directory.GetLastWriteTimeUtc` on the Download folder. A
directory's timestamp changes whenever an entry is added or removed in it, which is not the same as
the cache being written. Measured: folder 94 minutes, newest actual content **6.5 hours**. It was
blocking for six hours from an mtime bump unrelated to any download.

Now taken from the newest top-level entry — the per-update folders that appear when content lands,
a few hundred of them, cheap to stat. On this machine the blocker correctly disappeared.

### Advisories existed and reached nobody

`CleanupBlocker` documents its third parameter as *"False for an advisory the user may override"*.
Nothing ever constructed one, and every consumer filtered on `Blocking` — so an advisory would have
been computed and silently dropped. The confirmation dialog now shows them above the consequence
line. An advisory nobody is shown is a comment.

### The Needs column asked for the wrong thing

It read "admin" for every `NeedsAdmin` row — which the guardian service now handles with no user
involvement at all — and said nothing for rows held open by a running application, which is the one
case the user can actually do something about. The column now names what stands in the way *for the
user*: "in use" when blocked, "admin" only when there is no service to do it.

## 28. Four pipe handles were a denial of service

`MaxServerInstances` was 4, and the accept loop creates the next listening instance only once the
current one is taken. So four clients connecting and holding — writing nothing — left nothing
listening, and the service stopped answering everyone, including the dashboard's once-a-second state
poll.

That is the same end state as sections 20 and 25 (a dashboard that has gone blind), reachable on
request by anything able to open four handles.

Raised to 16, which is only half a fix — a hostile client holds sixteen as easily as four — so the
server now also reclaims a connection that connects and then stays silent. Every legitimate client
writes its request in the same breath as connecting and disconnects after one reply, so a 15-second
idle bound affects nothing real. Verified:

```
6 connections held open, saying nothing
  a normal ping           -> OK (197 bytes)
a held connection at  8s  -> still connected
a held connection at 20s  -> server closed it
```

## 29. A blocker that tripped on its own footprints

Asked to clear the Windows Update cache, HERO started, deleted 511 files and 3.6 GB, then stopped
itself:

> Stopped: The newest item here was written moments ago, so an update may be in flight.

The moments-ago writer was HERO. The executor re-checks blockers every 512 files, and the
`download-active` check reads file timestamps in the folder it is emptying — so deleting updated
the very value the check was reading. Worse, the partial run left fresh timestamps that then
refused the NEXT attempt too, with a six-hour window.

Three versions of this check, all measuring something HERO was simultaneously modifying:

| | measured | failed because |
|---|---|---|
| 1 | the Download folder's own mtime | changes on any entry add/remove — read "94 minutes" when the newest real content was 6.5 hours old |
| 2 | the newest child entry's mtime | accurate before the run, self-defeating during it — aborted after 511 of 734,915 files, then poisoned the retry |
| 3 | **whether wuauserv or BITS is running** | — |

The third is the signal that was wanted all along. Those two services are what move update
payloads; if neither is running nothing can be downloading, whatever the timestamps say, and HERO
deleting files cannot start a service. Measured while the cache held 10.46 GB: both Stopped.

Two lessons, and the second is the general one:

- `CleanupBlocker` gained `RecheckDuringRun`. The executor re-checks blockers mid-run to catch a
  conflicting process that STARTED — a build kicking off inside a package cache. That is worth its
  cost for anything observing other programs and actively harmful for anything observing state the
  deletion itself changes.
- **A check whose input the checker also writes will eventually refuse its own work.** Both failed
  versions looked reasonable in isolation; what made them wrong was who else was touching the thing
  being measured.

## 30. Installer and uninstaller

HERO now installs itself. `HERO.exe --setup` opens a themed setup window; run on a machine with no
HERO it offers to install, run on one that has it it offers to reinstall or remove.

**Built into HERO.exe rather than shipped as a separate setup program**, and the reason is the
theme. `App.xaml` merges `UI/Theme.xaml` at application level, so a window opened in this process
gets the same tokens, type scale, button tones and chrome as the dashboard and cannot drift from
them. A separate installer would have to copy the palette and would be wrong the first time either
changed. It also means there is one file to hand someone.

The window does no privileged work. Install and uninstall each re-launch HERO elevated with a
switch and wait for the exit code, so exactly one UAC prompt appears at the moment the button is
pressed — not at start-up, and not once per step. A dismissed prompt arrives as a Win32Exception
rather than a non-zero exit, which is why "you said no" and "it failed" can be told apart and
worded differently.

What install does, in order: stop any existing service, copy the program files, then hand the
service registration to the EXISTING `--install-service` path rather than reimplementing it — that
path already creates the state directory, migrates legacy state and applies the lockdown from
section 21, and two implementations of "install the service" is how one of them silently rots. Then
the Add/Remove Programs entry and a Start menu shortcut.

Details worth knowing:

- **The uninstall entry is written under `HKLM\...\Uninstall\HERO`** with a `QuietUninstallString`,
  so HERO can be removed from Settings > Apps like anything else. An application that can only be
  removed by its own hidden switch is one people delete by hand, leaving a service behind.
- **The program files are removed by a detached `cmd` that waits for the uninstaller to exit**,
  because a process cannot delete the directory it is running from.
- **The shortcut is written through a throwaway WSH script.** A `.lnk` is a COM-authored binary
  format and the IShellLink interop assembly is not in the shared framework; pulling a package in
  for one shortcut would break the zero-dependency rule for very little, and wscript is present on
  every Windows install.
- **Uninstall is deliberately tolerant** — each step is attempted and logged independently. An
  uninstaller that stops at the first missing piece leaves the machine half-uninstalled and the
  user with no way forward.
- **`%ProgramData%\HERO` is KEPT on uninstall**, and the confirmation says so. The timeline,
  quarantine vault and learned baseline are the product of days of observation; deleting them
  because someone removed the program would be the worst kind of surprise. The dialog names the
  folder so it can be removed deliberately.

### What testing it found

The first real run failed, and instructively:

```
setup: existing service stopped
setup: install failed: IOException: The process cannot access the file
       'C:\Program Files\HERO\HERO.dll' because it is being used by another process
```

`ServiceControl.Stop()` sends SERVICE_CONTROL_STOP and returns — the service process is still alive
and still holding HERO.dll for some time afterwards. Setup copied over that file immediately.

The worse half was what it left behind: setup stops the guardian BEFORE copying, so a failure
between those two points leaves the machine **unwatched**, and silently — the only visible symptom
is a service that is no longer running. Nothing said so.

Three fixes:

- `StopEverything` now polls `Query().Running` until the service has actually gone (20s bound,
  polled rather than slept so a fast stop costs nothing), then closes any HERO window holding the
  same directory, then pauses briefly for handles to drop.
- `CopyWithRetry` retries a sharing violation ten times at 300ms. Windows can keep an image mapped
  for a moment after the process exits, and that is the difference between an install that works and
  one that fails on a machine that was merely busy.
- The `catch` restarts the guardian if the attempt stopped it. Best effort, and logged either way —
  a security tool that quietly switches itself off during a failed upgrade is the worst outcome
  available here.

### Verified end to end

```
install    exit 0   service Running, uninstall entry written, shortcut created, files updated
uninstall  exit 0   service NOT REGISTERED, entry gone, shortcut gone, startup entry gone,
                    Program Files removed by the deferred cmd, %ProgramData%\HERO KEPT
reinstall  exit 0   service Running, all artefacts back, learned baseline survived,
                    state root still O:BA D:PAI(SY:F)(BA:F)(BU:R) with inheritance protected
```

The middle row is the one worth keeping: baseline.json, the vault, events and settings were all
still there after the uninstall, which is what the confirmation dialog promises.

### The deferred delete could have eaten a fresh install

Uninstall cannot delete the directory it is running from, so it schedules the removal for after it
exits — and that scheduled removal named the install directory by its ordinary name, the same name a
reinstall recreates. Uninstall, then reinstall before the timer fires, and the tail of the old
uninstall removes the new install.

Two bugs in one place, and the second was hiding the first. The wait loop was written as a single
`for /l` with the one-second delay placed AFTER the loop rather than inside it, so it spun sixty
times in about a second and gave up. It only ever appeared to work because the uninstaller happened
to exit first; a slow shutdown would have left the program files behind entirely.

Now the directory is renamed to a unique `HERO.removing-<pid>-<time>` sibling first, and the delete
is scheduled against THAT — a name no future install will ever create, so the race cannot exist.
When the rename fails, the delete names the real directory but proceeds only **if an uninstall
marker is still present**, and an install clears that marker as its first act. Install also sweeps
stale `HERO.removing-*` siblings so a failed uninstall cannot accumulate copies. The script is now a
real .cmd with the sleep inside the loop, and it deletes itself when done.

Measured: the rename path **never** succeeds here —

```
setup: could not rename the install directory (IOException); using a guarded delete
```

— because the uninstaller is running from inside the very directory it is trying to rename. So the
guarded path is the live one and the "fallback" is not a fallback in practice. Worth knowing before
trusting the rename to carry the design.

Verified: a marker planted by hand is cleared by the next install (`cleared a pending uninstall
marker`), and an uninstall followed immediately by a reinstall leaves the fresh install intact
through a full minute. NOT verified by execution: the batch's own marker check, because the delete
completes about a second after the uninstaller exits and no reinstall can be got in ahead of it.

## 31. The outcome store, and the reward system that was not built

The ask was self-learning with "a reward system so it doesn't get lost". A full design was produced
— a per-rule `Influence` multiplier in [0.64, 1.00], earned only by elevated approvals, decaying
back to nominal, with acting as a counter-vote — and an adversarial review took it apart. The
failures are recorded because they constrain anything built here later.

**The only gesture that could earn a credit is one the product refuses to perform.** The dashboard
runs unelevated by design. "This is expected" sends `AllowScope.Hash`, which `GuardianCommands`
refuses without an elevated caller, and the UI then steers the user to "Hide for a week" — a
dismissal, which the design said may never move the model. It would have shipped a ledger that only
ever writes `credited:false` and a multiplier permanently pinned at 1.0, on the only configuration
that ships.

**Softening a family's winner inverts the score.** `Scorer` keeps only the strongest signal per
Family. Apply a multiplier after that choice and a file carrying one MORE true accusation can score
lower than one without it: soften `proc.unsigned-image` (weight 16, the Provenance winner on almost
every developer-machine finding) to 0.64 and the family contributes 3.41, where had that rule not
fired at all `proc.volatile-location` would have contributed 4.67.

**The store would have been attacker-writable where it matters most.** `LockDownStateDirectory` runs
only from the installer, so on a machine where HERO was never installed the state root inherits
`%ProgramData%`'s ACL and any unelevated process can author the aggregate directly — no approval, no
elevation, no verdict.

**Rules are pure functions of attributes an attacker controls**, so a decoy can be built whose
accusing set is a superset of a payload's, and crediting every accusing rule per approval makes the
cost of softening a whole rule set one gesture rather than one per rule.

### What was built instead

`Guardian/OutcomeStore.cs` records and nothing consumes it. A record nothing acts on cannot be
poisoned into anything, and the recording is worth having on its own: HERO makes a judgement, the
user responds, and until now that response vanished — a dismissal set a timer, an approval wrote an
allowlist entry, and neither left any trace of which RULE had been right. HERO could not answer "how
often is this check correct here", which is both the question a person wants answered about a tool
that keeps interrupting them and the foundation any future tuning needs.

Two properties are load-bearing:

- **A live verdict is required to write a line.** Dismiss and undismiss reach the service over the
  pipe without elevation and resolve nothing, so a fabricated subject key must write nothing at all.
  An append-per-call on an unauthenticated command is a disk-filling primitive, not a feature.
  Verified: dismissing `persist:Fake|Nowhere|Nothing` created no ledger at all.
- **Each line stamps whether the state root was actually closed** when it was written, read from the
  DACL rather than assumed. A line without that stamp is a line no future consumer may trust, and
  discovering the distinction later would be worse than recording it now.

Capped at 4 MB with rotate-once, the same discipline as ServiceLog.

Not verified: the positive recording path, because the machine raised no verdict during testing. A
copied notepad.exe in %TEMP% behind an HKCU Run entry did not clear the bar — correct conservatism
rather than a fault — and manufacturing something that would clear it means planting something
malicious-looking, which is not a reasonable thing to do to someone's machine to test a log line.

### Two real bugs the review found on the way

- `GuardianService.Allow` calls `_scorer.Allow(subject, scope)` with no `ruleId`, so
  `AllowScope.RuleForEntity` is refused at `Scorer.cs:812-813` and can never succeed. That is the
  only allow an unelevated user can make and the only scope that names a rule — the natural
  candidate for a future reward signal, currently dead.
- `GuardianCommands.Dismiss` clamps an unelevated request to one day and `ThreatsPage` discards the
  reply, so a user who asks for seven days is silently given one and never told.

## 32. The narrowest correction the product offers, finally reachable

`Scorer.Allow` has always taken a `ruleId` and always refused `AllowScope.RuleForEntity` without one
(`Scorer.cs:812-813`). Nothing ever passed it. So that scope had never once succeeded in the life of
the product.

It matters more than a dead parameter usually would, because of what it is:

- It is the **only** approval an unelevated caller may make. Every other scope now requires an
  elevated one, and the dashboard runs unelevated by design.
- It is the only scope that names a **rule** rather than blessing a file. `Hash` pins bytes;
  `PathAndSigner` pins a publisher; both grant standing trust. `RuleForEntity` says only "this
  particular check is wrong about this particular program" — it pins no hash, grants the path
  nothing, and does not call `MarkUserAllowed` (`Scorer.cs:866`).

So the narrowest, most honest thing a person can say about a false positive was the one thing HERO
could not record — while the blunt instrument was refused for want of administrator rights, and the
UI steered them to a dismissal instead.

The plumbing is three call sites (`GuardianCommands` reads `ruleId` from the request,
`GuardianService.Allow` forwards it, `Scorer.Allow` already handled it) and one UI affordance: each
piece of evidence on the Threats page now carries a "wrong about this" control, because the rule id
is a property of the SIGNAL, not of the finding — a verdict with six signals is six separate claims
and the user may disagree with exactly one.

Verified: the chain passes the id end to end and the no-ruleId refusal is untouched. NOT verified:
an accepted `RuleForEntity` approval, because the machine raised no finding to approve during
testing — the same gap as the outcome store, and it closes the first time a real one appears.

## 33. The reward system, built on what section 31 refused to build on

Section 31 designed a per-rule multiplier and the review killed it on four counts. Section 32 closed
the first and the fourth by accident: `AllowScope.RuleForEntity` now works, is reachable unelevated,
and names **exactly one** rule. So the gesture exists, and one gesture credits one rule. That left
two objections to answer, and the answers shaped the design more than the requirement did.

### What earns influence, and nothing else does

Only a `RuleForEntity` approval — the user saying "this check is wrong about this program". Not
dismissals: crediting those credits impatience. Not blanket approvals: one click about one file must
not quieten a rule everywhere. It is the only correction that names a rule, so it is the only one
whose meaning is "this check is wrong" rather than "this program is fine" or "not now".

Counted **once per distinct program**, which is why `Entry` carries an `EntityKey` distinct from the
subject key. A process subject is `proc:<pid>:<start ticks>` — different every time the same program
runs — so counting subject keys would have let one program be corrected five times and read as five.

`MinPrograms = 3`, `StepPerProgram = 0.05`, `Floor = 0.80`, half-life 60 days. A rule at the floor
still contributes four fifths of its weight. This tunes HERO's noise; it does not switch checks off.

### The three properties that make it safe to have at all

- **Decisive signals are exempt**, applied at the call site in `Scorer` and mirroring the existing
  signer-attenuation exemption on the very next line. HERO acts autonomously only on a decisive
  signal, so no amount of correction can stop it acting on a hard indicator. Everything else is
  bounded by that one sentence.
- **It is ignored entirely unless the state root is actually closed to the user**, read from the
  DACL, not assumed. This is section 31's third objection, answered rather than argued with: a number
  read from a file the adversary can write is not evidence. On an uninstalled machine the influence
  table is not consulted and the Settings page says so instead of showing an empty list that reads as
  "you have never corrected me".
- **The threshold is a plain count of distinct programs; only the magnitude decays.** Gating on the
  decayed sum instead looks equivalent and is not: three corrections made this morning total
  `3 - 1e-7` credits, fractionally short of three, and would soften nothing — the feature would
  appear broken on the exact case it is specified for. Decay still bites through the magnitude, where
  three corrections a half-life old are worth 1.5 credits and clamp straight back to 1.00.

### The inversion, and why the fix is in the selection rather than the multiplier

Section 31's second objection was the serious one. `Scorer` keeps only the strongest signal per
family, and a multiplier applied *after* that choice means the softened winner keeps suppressing its
stronger siblings — so a file carrying one MORE true accusation scores LOWER than one without it.

The fix is one line: the family representative is chosen on `Weight * Influence`, not `Weight`.
Measured on a fabricated finding carrying both Provenance signals, `proc.unsigned-image` (16) and
`proc.volatile-location` (14), with the heavy rule driven to the floor:

```
untrained   both signals 12.850   volatile-location alone 12.180   (heavier rule wins its family)
softened    both signals 12.180   volatile-location alone 12.180   (weaker sibling takes over)
```

`16 x 0.80 = 12.8 < 14`, so the softened rule stops representing the family and the score converges
on the honest floor rather than dropping below it. The counterfactual is arithmetic rather than a
measurement, since the broken selection no longer exists to run: choosing on nominal weight would
have kept `proc.unsigned-image` as the representative at `16 x (1/3) x 0.80 = 4.27` rule points,
where `proc.volatile-location` alone contributes `14 x (1/3) = 4.67`. Two thirds of a point of
*safety*, bought by carrying an extra true accusation.

### Reset without erasure

"Forget what you've learned" appends a `reset` marker; `BuildInfluence` ignores everything at or
before the newest one. The record of what actually happened is evidence, and a security tool that
erases its own history on request has a feature an attacker wants.

Ungated over the pipe, deliberately: a reset only ever makes HERO **stricter**, so the usual question
— what does this let an attacker achieve — answers itself. What it could still have been is an
append-on-demand primitive, so a reset with nothing to forget writes nothing. That guard also fixed a
dishonest message: the first version answered "HERO has forgotten what it learned" on a machine that
had learned nothing.

### One click on a real finding found what four reviews had not

Sections 31, 32 and the first draft of this one all ended with the same caveat: no real finding had
ever been corrected, so the positive path was unexercised. A `GooglePlayGamesServices-26.8.707.0`
service finally raised one. Clicking "wrong about this" on its `evade.service-installed` signal wrote
**two** lines, not one:

```
{"k":"allow","r":"evade.service-installed",       ... "d":"RuleForEntity:evade.service-installed"}
{"k":"allow","r":"persist.unquoted-service-path", ... "d":"RuleForEntity:evade.service-installed"}
```

`Record` fans out over every signal in the verdict — correct for the tallies, because what else was
firing is genuine context — and `BuildInfluence` filtered on `Detail.StartsWith("RuleForEntity")`
without checking that the credited rule was the one the detail names. So one click credited a rule
the user had said nothing about.

That is **section 31's fourth objection alive and well**: one gesture softening a whole rule set, at
a cost of one click rather than one per rule. This document had already declared it dissolved on the
grounds that `RuleForEntity` names exactly one rule. It does — the gesture was never the problem, the
replay was. A decoy engineered to fire alongside a payload's rules would have earned credit for all
of them.

The fix is an equality rather than a prefix: `Corrections()` credits an entry only when
`Detail == "RuleForEntity:" + RuleId`. It also drops the detail-with-no-rule-id case, which
`Scorer.Allow` refuses anyway and so can only be legacy or forged.

The lesson is the one this project keeps relearning in a new costume: **a design property does not
survive into the code by being true of the design.** "One gesture names one rule" was true and was
still not what the replay computed. Nothing found it — not the adversarial review, not 25 passing
tests built from the same assumption — until the feature was pointed at a real finding once.

### Verified

28 assertions against a synthetic ledger, run elevated because the ledger is closed to Users on an
installed machine — which is also the only configuration where any of this is consulted. Thresholds,
the one-vote-per-program rule, the floor, decay in both directions, resets, torn and non-JSON lines,
that a correction credits only the rule it named, and that dismissals, blanket approvals, scoped
approvals naming no rule, and lines written while the root was open all earn exactly nothing. Plus
the inversion property above, end to end through `Scorer.Score`.

The regression test above was written from the two real lines verbatim. Note that the first run after
the fix failed **twelve** assertions, all because the synthetic ledger had been writing
`"d":"RuleForEntity"` with no rule id — a fixture that had never matched what `GuardianService.Allow`
actually stamps. Tests built from an assumption confirm the assumption.

Verified over the pipe unelevated: `learning` returns `sealed: true` and now lists the real
correction, `learning.reset` declines to write when there is nothing to forget.

**And the suppression itself, which sections 31 and 32 could never test.** The correction wrote
`al_ed6ace7fa43b` into the baseline — scope `RuleForEntity`, entity `p:4d92bcd9af7a21b3`, rule
`evade.service-installed`, 180 days, pinned to the file's content identity so it revokes if the
binary changes. Three minutes later HERO re-raised the same subject with that signal gone: score
`6.0 -> 4.82`, two signal families down to one, `persist.unquoted-service-path` untouched.

The timing had to be checked rather than assumed, because `ServiceInstalledRule` fires only while an
Event ID 7045 sits inside a 30-minute lookback, and a signal that had simply aged out would look
identical to one that was suppressed. The 7045 for Google Play Games Services was `21:55:23Z`, so the
window ran to `22:25:23Z`; the approval was `22:05:36Z` and the re-raise `22:08:52Z` — seventeen
minutes before the rule would have stopped firing on its own. The allowlist did it.

Still not verified: influence actually moving a number, which needs three distinct programs. One
exists.

## 34. The service-install rule could only see badly configured services

Sixteen Event ID 7045 entries for HERO's own guardian service in one evening produced no finding.
The suspicion was a deliberate self-exclusion. There is none. The rule simply could not match.

`ServiceInstalledRule` attributed a 7045 to a subject like this (`EvasionRules.cs:584`, before the
fix):

```csharp
bool mine =
    (entry is { Category: PersistenceCategory.Service }
        && (entry.Name.Equals(e.ServiceName, ...)
            || (e.ImagePath.Length > 0 && entry.ImagePath.Equals(e.ImagePath, ...))))
    || (p is not null && e.ImagePath.Length > 0 && p.ImagePath.Equals(e.ImagePath, ...));

if (!mine) continue;
```

Both comparisons are between values that are not the same kind of thing.

**The name branch compares two different fields.** `entry.Name` is the registry KEY name; a 7045's
`ServiceName` is the DISPLAY name. `HeroGuardian` vs `HERO Guardian`.
`GooglePlayGamesServices-26.8.707.0` vs `Google Play Games Services (26.8.707.0)`. It matches only
where a service happens to name both identically — 36 of 780 on this machine.

**The path branch compares a command line against an extracted path.** 7045 carries the registry
`ImagePath` verbatim, and the scanner had already normalised the entry's:

```
"C:\Program Files\HERO\HERO.exe" --service      the event, raw
C:\Program Files\HERO\HERO.exe                  the entry, normalised
```

Measured with HERO's own extraction over every service in the registry: **raw equals extracted for 44
of 780**. So the path branch could attribute at most 44 services, and the whole rule at most about
eighty — in a family named EVASION.

Google Play Games was detected only because its registry value is bare and unquoted, which is exactly
what `persist.unquoted-service-path` fired on. **HERO's hardening rule recommends the change that
makes a service invisible to HERO's evasion rule.** Quoting the path, or passing any argument, is
enough — and that is what every competent installer does: Cloudflare WARP, Epic Online Services,
Chrome's elevation service, Office ClickToRun, EasyAntiCheat, and HERO.

### There IS a deliberate self-exclusion, and the first version of this section denied it

Written down because the error is instructive. HERO's own service **is** in the persistence
inventory — I checked, found it there, and concluded from its presence that nothing excluded it. The
inventory is not the subject set. One line sits between them:

```csharp
foreach (var entry in entries)
{
    // HERO's own run-at-logon entry is not a finding.
    if (StartupRegistration.IsOwnStartupArtifact(entry)) continue;   // GuardianService.cs:917
    ...
    var subject = new PersistenceSubject(entry);                     // :929
```

`IsOwnStartupArtifact` has a service arm (`StartupRegistration.cs:641-648`) keyed on the registry
name `HeroGuardian`, with two path anchors: the running executable, and the install directory
recorded in the elevated integrity manifest. Verified at runtime rather than read: called with a real
entry built from the real registry it returns **true** for HeroGuardian and **false** for the Google
Play service — and it returned true from a test harness that is not HERO.exe, so it matched on the
manifest anchor, exactly as its comment claims.

So the observation was **overdetermined**. The broken match and the deliberate exclusion each
independently account for HERO's own service producing nothing, and neither is necessary. The
measurement that convinced me — "HeroGuardian is in the inventory" — was true and did not support the
conclusion I drew from it. A parallel investigation found the missing line; four separate reads of
the scanner and the rule by me did not, because I never asked what happened between them.

### The fix, and where it had to go

The comment immediately below the gate already described the problem —

```csharp
if (!mine) continue;                                                      // :591
// 7045 carries a service COMMAND LINE, not a path: Windows writes it quoted and with
// arguments ..., and drivers arrive as \??\C:\... .                      // :593
var imagePath = PersistenceScanner.ExtractExecutable(rawImage);           // :599
```

— and `ExtractExecutable` ran **eight lines after the gate that needed it**.

**The obvious repair was wrong, and shipping it proved how wrong.** Moving the extraction above the
gate makes both sides comparable, and it over-matches, because *an executable is not a registration*.
Deployed at 22:26, and by 22:42 HERO had raised a finding against **its own dashboard process** for
the installation of its own service:

```
score 5.33  Low   pid 30196   image C:\Program Files\HERO\HERO.exe
[w=4] evade.service-installed   evidence: HERO Guardian · C:\Program Files\HERO\HERO.exe
```

Normalising the whole command line instead narrows it and does not fix it. Measured over all 780
service registrations on this machine:

| matched on | ambiguous groups |
|---|---|
| executable | 10 — including 251 services behind `svchost.exe`, six behind `lsass.exe` |
| full command line, normalised | 37 |
| display name | 1 — `SerCx` / `SerCx2`, both "Serial UART Support Library" |
| **display name + executable** | **0** |

So the shipped rule matches on **identity, confirmed by image**: the service name (short or display)
identifies the registration, the executable confirms it. Neither half is sufficient and each covers
the other's blind spot. `PersistenceEntry` now carries `DisplayName`, because 7045 reports the
display name and the registry is keyed by the short one, and nothing else in the event is unique.

The process arm is **gone**. It matched a running process whose image equalled the new service's,
which is how HERO flagged its own dashboard; a process's command line names a binary, and a binary is
not a registration. A service install is a persistence fact and belongs on the entry that was
created.

`ExtractExecutable` is now reached through one named function, `PersistenceScanner.ServiceExecutable`,
called by the scanner when it builds an entry and by the rule when it confirms one. Two copies of an
identity function drift in silence, because nothing throws — the comparison merely stops being true.

Known limits, stated rather than discovered later: an in-box service whose registry `DisplayName` is
an indirect string (`@%SystemRoot%\system32\x.dll,-100` — 601 of 715 on this machine) cannot be
matched by name, and `PersistenceScanner` skips services with `Start > 2`, so a trigger-started
service has no subject at all. Neither is a regression; before this work nothing matched.

### Verified

- Assertions over the shapes Windows actually writes, including `\??\C:\...` and `\SystemRoot\...`
  driver paths; agreement across all 780 services in the registry; and the identity table above
  computed from the live registry rather than asserted.
- End to end against the live machine: HERO's service registration was cycled, producing a real 7045
  at `22:26:42Z` with `"C:\Program Files\HERO\HERO.exe" --service`. Running the real rule against the
  real event feed and a subject built from the real registry emits
  `[w=4] evade.service-installed  family=evasion` where before it emitted nothing.
- The over-match was verified by *observing it happen* (score 5.33 against HERO's own dashboard), not
  predicted — and the regression tests were written from that measurement.

- The corrected build, in the running service, against the exact conditions that produced the
  regression: service registration cycled for a real 7045 at `06:24:12Z`, then a HERO.exe dashboard
  started at `06:24:38Z` — inside the lookback, the same sequence that scored 5.33 before. Verdicts
  held afterwards: one, the Google Play unquoted-path finding. No HERO finding of any kind, while
  the rule itself demonstrably still emits `evade.service-installed` when asked directly.

### Why HERO stays quiet about its own service

Two independent reasons, and only the first is about this rule. `GuardianService.cs:917` drops
HERO's own service before a subject exists, so nothing scores it at all. Even without that, a
weight-4 signal alone falls below `ScorerModel.LowScore` (4.0) and `MapConfidence` returns
`Informational`.

The distinction that matters is for everyone else's services. A service installed from a
user-writable directory hits `weight = 10`, and from a volatile one `weight = 18` with
`Severity.Critical` — and those were unreachable for any correctly-quoted service, by anyone, before
this fix.

## 35. HERO's identity was a folder, not a set of files

Section 34's investigation turned up a second thing on the way past: the self-exclusion that stops
HERO reporting its own service anchored on a DIRECTORY.

```csharp
// StartupRegistration.IsOwnStartupArtifact, service arm
string exe = ExtractExe(target ?? "");
if (SamePath(exe, self)) return true;
if (IsInside(exe, Service.SelfIntegrity.RecordedInstallDirectory)) return true;   // <- too wide
```

The second line exists for a real case, stated in its own comment: a developer running the
`bin\Debug` copy while the installed service points at Program Files is ordinary, not an impostor.
But "inside the recorded install directory" hands HERO's identity to anything that can be written
there. Asked directly, before the change:

```
HERO's real service binary is recognised                        PASS
a FOREIGN binary in HERO's install directory is NOT recognised  FAIL
a foreign binary wearing HERO's service name IS impersonation   FAIL
```

So an attacker who could write to `C:\Program Files\HERO` could drop `evil.exe` beside `HERO.exe`,
repoint `HKLM\System\CurrentControlSet\Services\HeroGuardian` at it, and HERO's own LocalSystem
automatic-start service would run a foreign binary at every boot -- while `IsOwnStartupArtifact`
called the entry ours, so no persistence rule ever scored it, and `IsImpersonation` returned false,
so the "something is wearing HERO's name" signal stayed silent too.

**The honest weighting.** This needs administrator rights, and so does installing any service; an
attacker holding admin has better options than this. It is not a privilege escalation. What it is is
the removal of a warning: the window in which a still-running HERO could have said *my own service
now points at something that is not me* is exactly the window the directory anchor closed. A security
tool going quiet about its own subversion is worth fixing whatever the attacker's alternatives are.

### The fix uses a record that already existed

`SelfIntegrity` writes a manifest at install time listing every file in the install directory by
relative path. Identity now anchors on that list -- `SelfIntegrity.IsRecordedFile` -- rather than on
the folder. The developer case still works, because `HERO.exe` is in the manifest; `evil.exe` is not.

Deliberately NOT hash-checked. A legitimately updated `HERO.exe` has a new hash and is still HERO;
noticing changed content is `SelfIntegrity.Check`'s job, and conflating the two would make every
update look like an intrusion. The file LIST is the right granularity for the question "is this one
of mine".

An empty or missing manifest returns false rather than trusting the directory -- no evidence is not
blanket trust -- which leaves `SamePath` as the only anchor on a machine that was never installed.
And what this still cannot do is what the class already says in its own summary: an attacker who
rewrites the manifest too is caught by none of it.

All four identity assertions pass after the change, including `IsImpersonation` now firing on the
foreign binary. Nothing was created on disk to test it: `IsOwnStartupArtifact` is a pure function of
three strings, so the hypothetical registry state was simply asked about.

## 36. Two bugs found by using the product

Both reported by the user in one sitting, both real, and neither would have been found by reading
code.

### "I did remove with admin and it is still showing"

Pressing "Remove this auto-start" on the Google Play Games service worked perfectly: the registry
`Start` value went to 4, and the very next sweep correctly dropped the entry from the inventory,
428 entries to 427. The finding stayed on the Threats page anyway, still stamped with the timestamp
of the sweep BEFORE the removal.

Nothing deleted the verdict, because nothing ever could:

```csharp
/// <summary>Drops verdicts about processes that have since exited...</summary>
private void PruneVerdicts(Snapshot current)
    ...
    foreach (var key in _verdicts.Keys
                 .Where(k => k.StartsWith("proc:", StringComparison.Ordinal) && !live.Contains(k)))
```

`proc:` only. A `persist:` verdict was immortal — it outlived the entry being disabled, deleted,
uninstalled by its own vendor, or simply falling below the reporting threshold. It survived for as
long as the service process ran.

The fix is a change of principle rather than an extra case: **the persistence verdicts ARE the last
sweep's output.** `ReplacePersistenceVerdicts` rebuilds them from the set the sweep actually raised,
so staleness has nowhere to accumulate. It runs only after a COMPLETE sweep — a partial one would
clear findings it merely failed to see — which is why the call sits inside the try, after the loop.

A successful action on a persistence subject now also kicks an immediate rescan, so the finding
disappears within seconds instead of up to ten minutes. Deliberately routed through a rescan rather
than deleting the verdict directly: HERO then never claims a removal succeeded on its own say-so.
The finding goes because the entry is gone.

Verified end to end on the live machine: the service was re-enabled (`Start=2`), HERO raised it
again with a fresh timestamp, the service was disabled (`Start=4`), and the next sweep left
`verdicts held: 0`.

**Why this one matters more than its size.** A security tool that keeps showing a finding after you
have acted on it teaches you that its buttons do not work. That is worse than not offering them.

### "Clicking the maintenance page after a while causes the program to lag"

`MaintenancePage.ShowDrives` read `DriveInfo.TotalSize` and `AvailableFreeSpace` on the UI thread.
Those are not property reads; they are synchronous `GetDiskFreeSpaceEx` calls, and on a drive that
has spun down Windows blocks them until the platters are back. This machine has four fixed drives,
three of them large HDDs (11 TB, 3.8 TB, 3.7 TB). Warm, all four read in 51 ms total. Cold, each can
take seconds — serially, with the message pump stopped. Hence "after a while": that is when a disk is
asleep.

The reads now happen on a background thread and the bars fill in when the disks answer, so
navigation paints immediately. The measuring pass was already off the UI thread; only the drive
header was not.

### The pattern

Neither bug is subtle once seen, and neither showed up in any amount of reading. One needed somebody
to press a button and notice the result did not change; the other needed a machine with sleeping
disks and somebody who had walked away from it. Sections 31 to 35 were all found by measurement
rather than review, and these two extend that: the product has to be USED, on a real machine, by
someone who will say "that is not right".

## 37. Trigger-started services: a 41% hole in the service inventory

`PersistenceScanner.ScanServices` skipped every service with `Start > 2`, on the stated grounds that
"only Automatic and Boot/System actually persist without user action". That is true of Manual
services in general and false of one important subset.

A service can carry a **start trigger**: Windows launches it when a device arrives, an IP address is
assigned, a named pipe is opened, a firewall port opens, a domain policy refreshes. `Start = 3`,
nobody asks, it runs anyway. That is persistence by any honest definition, and it is quieter than an
Automatic service — which makes it a good place to hide and a bad place to be blind.

Measured on this machine:

| | count |
|---|---|
| scanned before (`Start <= 2`) | 238 |
| **trigger-started, invisible** | **98** |
| Manual with no trigger (genuinely on-demand) | 418 |
| Disabled | 26 |

### Measuring the cost before paying it

The obvious worry with adding 98 entries is a wave of new findings, and a first shell estimate said
91 of them would trip `persist.unquoted-service-path`. That estimate was **wrong** — it counted
command-line arguments as part of the path.

So the question was answered with HERO's own machinery instead: every candidate built into a real
`PersistenceEntry`, run through the real `RuleCatalogue`, with real signature verification and the
real baseline loaded from disk, and scored by the real `Scorer`.

```
CONTROL - services HERO already scans : 0 of 238 reported (1 produced a signal)
NEW     - trigger-started services     : 0 of  98 reported (0 produced a signal)
```

Zero. All 97 in-box ones live in System32, and `UnquotedServicePathRule` exempts
`PathClass.SystemProtected` explicitly — an unquoted path there cannot be hijacked. The single
third-party one, `edgeupdatem`, is properly quoted.

**The control is what makes that trustworthy**, and "0 findings in the control set" alone would not
have been: HERO also reports 0 today, so 0 == 0 proves only that the harness is capable of silence. A
positive control was added — the Google Play Games finding, rebuilt from its registry values — and it
reproduces signal for signal. It scores 6.10 where production scored 4.82, because the harness has an
empty process snapshot and a freshly decayed baseline. That gap was left in rather than tuned away:
the harness runs HOT, so "0 of 98" is a ceiling, not an estimate.

### The change

`Start = 3` is now included when the service has at least one start trigger. Manual without a
trigger stays out — 418 services that genuinely do not start on their own are inventory, not
persistence. Disabled stays out.

`HasStartTrigger` counts the SUBKEYS of `TriggerInfo` rather than testing the key for existence,
because Windows leaves empty `TriggerInfo` keys behind when triggers are removed and one of those is
not a trigger.

Verified against the live service after deploying: persistence entries 427 to 525, service entries
238 to 336, all 98 present, 0 of 418 on-demand services leaked in, disabled still excluded — and
`verdicts held: 0`. Exactly the coverage, exactly none of the noise.

## 38. 601 of 715 services had a name HERO could not read

Section 34 left `ServiceInstalledRule` matching an Event 7045 on the service NAME, and noted a limit:
a service's registry `DisplayName` is usually an indirect string, and the event reports the resolved
text. `@%SystemRoot%\system32\AarSvc.dll,-100` never equals `Agent Activation Runtime`. On this
machine that was 601 of 715 services -- so the name match worked almost exclusively for third-party
installers, which write a literal.

### Two formats, and only one of them is what the documentation describes

`SHLoadIndirectString` (shlwapi, in-box, no package -- HERO takes none) resolves the documented form:

```
@%SystemRoot%\system32\AarSvc.dll,-100        ->  Agent Activation Runtime
```

It resolved 374 of 603. The other 229 returned a failure HRESULT, and looking at them explained why:

```
@1394.inf,%PCI\CC_0C0010.DeviceDesc%;1394 OHCI Compliant Host Controller
```

Driver services are registered from an INF, and Windows stores the localisation key **together with
the English text it stands for**, after a semicolon, exactly so the name survives when the INF cannot
be consulted -- which it cannot, because the value names the file without a path and it lives in
`%SystemRoot%\INF`. The trailing text is Windows' own fallback, not a guess. Using it took resolution
to **592 of 603**, and dropped the cold pass from 933 ms to 19 ms because most entries no longer load
a module at all. Cached per process thereafter: 0 ms.

### The oracle, and the two things it caught

Correctness was not asserted, it was checked against the operating system: `Get-Service` and
`Win32_SystemDriver` report the name the SCM has resolved, which is the same string an event carries.
First pass, 562 of 564 matched. The two that did not were both the same mistake in a new costume --
**normalising one side only**, section 34's lesson exactly:

- `MEIx64` -- the SCM keeps a trailing space, `"Intel(R) Management Engine Interface "`. The resolver
  had trimmed it. The resolver no longer trims; the CALLER does, on both sides.
- `Tcpip6` -- registered as `@todo.dll,-100;Microsoft IPv6 Protocol Driver`, a placeholder Windows
  itself cannot resolve, so the SCM reports the raw string and an event would too. HERO resolved it
  and was therefore "more correct" and would have matched nothing.

The fix for both is to run the EVENT's name through the same resolver as the entry's, so the two
agree whichever form arrives. Re-checked with both sides normalised the way the rule normalises:
**564 of 564**.

Eleven names still do not resolve: their module exists but the resource id is absent and there is no
semicolon fallback (`Acx01000`, `UCPD`, `WaaSMedicSvc` and eight more). They keep their raw value,
match nothing, and are exactly as invisible as every one of the 601 was before -- a residue, not a
regression. Three survive into the live inventory.

Verified live after deploying: 336 service entries, 3 with an unresolved name, 0 new verdicts.
`wuauserv` now reads "Windows Update", `AFD` reads "Ancillary Function Driver for Winsock".

### Worth stating plainly

The impact was measured before shipping, the same way as section 37: if a 7045 fired for every
service on this machine, 17 of 336 would clear the reporting threshold -- and the top of that list is
third-party software (CCleaner, Cloudflare WARP, TeamViewer, AMD), which is precisely what a rule
called "a new service was installed" is for. In-box services sit below it. This buys reach without
buying noise.

## 39. Git Bash was broken by Mandatory ASLR, not by Git

Measured 2026-09-25. §13 told every reader for months to use PowerShell for all tooling because
"Git Bash is broken on this machine". True as a symptom (`fork: Resource temporarily unavailable`,
exit `0xC0000142`), wrong as a diagnosis, and it shaped how work got done in this repo.

### Cause

Exploit Protection had `ASLR.ForceRelocateImages` (Mandatory ASLR) **ON** system-wide. MSYS2
emulates `fork()` by requiring `msys-2.0.dll` at the *same* base address in parent and child;
forced relocation makes that impossible, so every child died before `main` with
`STATUS_DLL_INIT_FAILED`. Nothing was wrong with Git.

### Why it hit MSYS and nothing else

Read from PE `DllCharacteristics` on this machine, verified two independent ways (a hand PE parse
at `e_lfanew+24+0x46`, and `System.Reflection.PortableExecutable.PEReader`):

```
Git\usr\bin\bash.exe, cat.exe, sed.exe        0x8000  DYNAMIC_BASE=False
System32\find|sort|tar|timeout|whoami
         |hostname|expand|reset .exe           0xC160  DYNAMIC_BASE=True, HIGH_ENTROPY_VA=True
```

`ForceRelocateImages` only forces relocation on images built **without** `/DYNAMICBASE`. The
System32 binaries sharing those names opt into ASLR natively, so exempting the name is a **no-op**
for Windows. That is what made the fix safe, and why the first read of the problem — which assumed
those collisions carried real security cost and declined to act — was wrong.

Confirmed behaviourally rather than inferred: `System32\timeout.exe`, which now carries a
`ForceRelocateImages` exemption, still loads at `0x7FF718C90000` against a preferred `ImageBase`
of `0x140000000`. Ordinary ASLR relocates it regardless. The exemption removed nothing.

**Not every Git binary needed it.** Of the 301 `.exe` under `Git\{usr\bin,bin,mingw64\bin}`, 242
are `0x8000` with no `DYNAMIC_BASE`. The remaining 59 files — 58 unique names, 57 of them in the
applied list — already had `DYNAMIC_BASE` and gained nothing. (Files and names differ here, and
the distinction matters because IFEO keys are per **name**.) That includes one of the two
`bash.exe` images: `usr\bin\bash.exe` is `0x8000`, the one that mattered, while `bin\bash.exe` is
`0x8160`. And there is no `curl.exe` on the Git side except `mingw64\bin\curl.exe` at `0x0160`, so
of the nine name collisions only **eight** were ever load-bearing.

### The diagnostic, if it recurs

A non-MSYS child works while every MSYS child dies:

```
$(cmd.exe //c echo hi)  ->  hi          # general process creation is fine
$(echo piped | cat)     ->  (empty)     # MSYS child
/usr/bin/cat /dev/null; echo $?  ->  127
```

The doubled slash is not a typo and the control line is worthless without it: MSYS rewrites a lone
`/c` into a Windows path, so `cmd.exe /c echo hi` never receives the switch, starts interactively
and returns its banner. `MSYS_NO_PATHCONV=1 cmd.exe /c echo hi` works too. This was true before
the ASLR fix as well — it is an argument-conversion quirk, unrelated to the bug it diagnoses.

### The fix, and what the reversal does not cover

286 per-image `ForceRelocateImages` exemptions across `C:\Program Files\Git\{usr\bin,bin,mingw64\bin}`,
0 failures. **System-wide `ForceRelocateImages` remains ON** — only per-image exemptions were
added. Scripts and the record are in `D:\My projects\tools\aslr\`.

**The live count is 287, not 286, and the undo is therefore incomplete.** `bash.exe` was exempted
by hand while diagnosing, before the bulk run, so it is **not** in `applied-exemptions.json` and
`undo-msys-aslr.ps1` will not reverse it. Remove it separately with
`Set-ProcessMitigation -Name bash.exe -Remove` if a full revert is ever wanted. (`ssh-agent.exe`
also carries an entry and is correctly excluded — Windows shipped that one.)

Verified after: `echo $(echo piped | cat) $(date +%Y)` -> `piped 2026`; pipes, `sed`, `grep`, `awk`
and nested command substitution all work.

### Residual: login shells emitted 13 lines of noise, 4 of them on STDOUT — cleared

Once fork worked, Git's post-install scripts could finally *attempt* to run, but could not delete
themselves without admin, so `/etc/profile` re-ran them on every login shell:

```
bash -lc 'echo MARKER'   ->  14 lines   (13 noise + MARKER)
bash -c  'echo MARKER'   ->   1 line    (clean)
```

**It was not cosmetic.** Nine lines were permission-denied on stderr, but four were `cp` verbose
lines on **stdout** (`'C:\WINDOWS\system32\drivers\etc\hosts' -> '/etc/hosts'` and three more), so
any `X=$(bash -lc '...')` capture was silently polluted. Claude Code's Bash tool uses a login shell,
which is why it showed on every call there.

**Cleared 2026-09-25 23:02** by one elevated login shell,
`Start-Process bash.exe -ArgumentList '-lc','exit' -Verb RunAs`, exit 0. The four scripts in
`C:\Program Files\Git\etc\post-install` are benign and stay inside Git's own folder: create
`/dev/shm` and `/dev/mqueue`, link `/etc/mtab`, copy four Windows network files into Git's `etc`,
then `99-post-install-cleanup.post` deletes the directory — it fires only because
`C:\Program Files\Git\ReleaseNotes.html` exists, which was checked first. The time above is the
creation time of the files the scripts wrote. Re-measured 2026-09-27, so it held:

```
post-install directory      ->  gone
bash -lc 'echo MARKER'      ->   1 line    (was 14)
  stdout lines              ->   1         (was 5)
X=$(bash -lc 'echo ...')    ->  clean capture
```

**One side effect to know about.** Git's `etc\hosts`, `protocols`, `services` and `networks` are
now **copies** (`cp -p`), not links — `LinkType` is empty and the content is byte-identical today.
A later edit to `C:\Windows\System32\drivers\etc\hosts` will not reach MSYS tools until Git's copy
is refreshed.

### And exempting `bash.exe` alone is not sufficient

IFEO matches on image **name**, so every MSYS child (`cat`, `sed`, `grep`, `date`, ...) needs its
own exemption. Exempting only `bash.exe` fixes bash's own `fork()` — subshells work — while every
child still dies, which reads as a partial fix and is the most confusing state to stop in.
