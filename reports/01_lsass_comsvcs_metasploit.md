# Incident 1: LSASS credential theft after Metasploit access

**Dataset:** OTRF Security-Datasets, `datasets/compound/LSASS_campaign_03`,
file `metasploit_comsvcs_lsass_memory_dump.json` (MIT licence).
**Host:** PRD01.pandalab.com (Windows).
**Analysed with:** `soclab run --rules detections metasploit_comsvcs_lsass_memory_dump.json`
over 41,954 events.

## Summary

An attacker with an interactive Metasploit session on PRD01 ran local
discovery, installed a service that loaded a payload DLL through rundll32, and
dumped LSASS memory with the signed `comsvcs.dll` MiniDump technique to recover
credentials. The engine raised two detections on this data: the service
install (the lateral-movement / execution pattern) and the LSASS dump itself.

## Timeline

All times are Sysmon `UtcTime` as recorded in the dataset.

| Time (UTC) | Event | Detail |
|---|---|---|
| 15:57:00 | Process | `winx64_payload.exe` spawns `cmd.exe` (Metasploit session) |
| 15:57:02 | Discovery | `cmd.exe` -> `systeminfo` |
| 15:57:11 | Discovery | `cmd.exe` -> `whoami` and `whoami /groups` |
| 15:58:11 | **Service install** | `services.exe` -> `rundll32.exe C:\Users\PEDRO~1.GUS\AppData\Local\Temp\qfhaer.dll,a /p:qfhaer` (service `qfhaer`) |
| 16:00:03 | **LSASS dump** | `svchost.exe` -> `rundll32.exe ... comsvcs.dll MiniDump 628 C:\Windows\Temp\lsass-comsvcs.dmp full` |
| 16:00:08 | Process | `svchost.exe` -> `cmd.exe` |
| 16:03:11+ | Discovery | a long run of `reg export` of wireless and credential-provider keys via cscript |

## Rules that fired

```
[high] Service installed with a script host or encoded command in its ImagePath
    ServiceName=qfhaer  ImagePath=rundll32.exe C:\Users\PEDRO~1.GUS\AppData\Local\Temp\qfhaer.dll,a /p:qfhaer
    (System event 7045, 2023-08-18)

[high] LSASS memory dump via comsvcs.dll MiniDump
    rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 628 C:\Windows\Temp\lsass-comsvcs.dmp full
    (Sysmon event 1, 2023-08-18 16:00:03)
```

Two rules, two events. The dump command names PID 628 (lsass) and writes
`lsass-comsvcs.dmp`, which is the whole signature of the technique.

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution / Lateral Movement | T1569.002 System Services, T1543.003 Windows Service | service `qfhaer` installed with a rundll32 ImagePath |
| Credential Access | T1003.001 OS Credential Dumping: LSASS Memory | comsvcs MiniDump of PID 628 |
| Discovery | T1082 System Information, T1033 System Owner/User | systeminfo, whoami (seen in telemetry, not alerted on) |

## Scope

- One host in the data, PRD01. The service was installed by `services.exe` on
  behalf of a user context `PEDRO~1.GUS`, and the dump ran under a `svchost.exe`
  parent, consistent with a service-based execution.
- The dump file `C:\Windows\Temp\lsass-comsvcs.dmp` is the thing to find and
  treat as stolen: every credential cached in LSASS on that host (logged-on
  users, service accounts, any cached domain creds) must be assumed exposed.
- Check whether PRD01 is a server many accounts log on to. If so, the blast
  radius is every one of those accounts.

## Containment, eradication, recovery

1. **Contain:** isolate PRD01 from the network. Kill the `qfhaer` service and
   the Metasploit `winx64_payload.exe` process tree.
2. **Eradicate:** delete the `qfhaer` service and its DLL in
   `...\AppData\Local\Temp\`, and the `winx64_payload.exe` dropper. Find how
   `winx64_payload.exe` arrived (it is the earliest attacker process in the
   data) and close that path.
3. **Recover:** reset the passwords of every account that had a session on
   PRD01, prioritising any privileged or service accounts; rotate the machine
   account; if a domain admin had logged on, treat it as a domain-wide
   credential exposure and follow the AD recovery runbook (krbtgt reset, etc.).
4. Remove the collected dump and the `reg export` output files the attacker
   staged.

## Tuning notes

- The service-install rule fired on an ImagePath of `rundll32.exe ...dll,a`,
  which is exactly the shape a legitimate service never uses. No tuning needed;
  if a real environment has a product that wraps rundll32 in a service, baseline
  its service name.
- The long run of `reg export` of wireless profiles and credential-provider
  keys was **not** alerted on. That is correct for the credential-hive rule
  (it looks for `reg save` of SAM / SYSTEM / SECURITY, not `reg export` of other
  keys), but it is a real collection behaviour. A future rule could watch for a
  burst of `reg export` / `reg save` from one process, which would have caught
  this staging step too. Logged as a gap rather than hidden.
