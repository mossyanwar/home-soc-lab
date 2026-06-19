# Incident 5: UAC bypass via fodhelper

**Dataset:** OTRF Security-Datasets,
`datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper`
(MIT licence).
**Host:** WORKSTATION5.theshire.local (Windows).
**Analysed with:** `soclab run --rules detections <dataset>` over 4,139 events.

## Summary

An Empire agent elevated from a medium-integrity to a high-integrity process
using the fodhelper UAC bypass. It wrote the attacker command into the per-user
`ms-settings\shell\open\command` key, set an empty `DelegateExecute` value, then
launched `fodhelper.exe`, which auto-elevates and honours that key, running the
command elevated without a UAC prompt. The engine caught the four registry
writes that set up the bypass, plus the encoded PowerShell that ran as a result.

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 07:30:12.728 | Discovery | `powershell.exe` -> `whoami /groups` (checking integrity before) |
| 07:30:13.135 | **Hijack key created** | Sysmon 13, `HKU\...\ms-settings\Shell\Open\command` |
| 07:30:13.135 | **DelegateExecute set** | Sysmon 13, `...\ms-settings\Shell\Open\command\DelegateExecute` = `(Empty)` |
| 07:30:13.151 | **Command set** | Sysmon 13, `...\command\(Default)` = `powershell ... -c $x=(gp HKCU:Software\Microsoft\Windows Update).Update; powershell -enc $x` |
| 07:30:13.250 | Trigger | `powershell.exe` -> `fodhelper.exe` |
| 07:30:14.087 | **Elevated run** | `fodhelper.exe` -> `powershell.exe -NoP -NonI -W Hidden -c ...` (now high integrity) |
| 07:30:16.224 | Payload | `powershell.exe` -> `powershell.exe ... -enc <base64>` |
| 07:30:54.541 | Discovery | `whoami` again (confirming elevation) |

The order is the whole story: three registry writes, then `fodhelper.exe`
launched by the same PowerShell, then `fodhelper.exe` spawning the attacker's
PowerShell. The `whoami /groups` before and `whoami` after bracket the
elevation.

## Rules that fired

```
[high]   UAC bypass via shell open command hijack  (4 hits)
    TargetObject=HKU\...\ms-settings\Shell\Open\command
    TargetObject=HKU\...\ms-settings\Shell\Open\command\DelegateExecute   Details=(Empty)
    TargetObject=HKU\...\ms-settings\Shell\Open\command\(Default)         Details=powershell ... -enc ...
    (Sysmon event 13, 07:30:13 and a repeat at 07:30:18)

[medium] PowerShell encoded command
    powershell.exe -NoP -NonI -W Hidden -enc SQBGACg...
    (Sysmon event 1, 07:30:16)
```

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Privilege Escalation / Defense Evasion | T1548.002 Abuse Elevation Control Mechanism: Bypass User Account Control | writes to `ms-settings\shell\open\command` then fodhelper launch |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | the `-enc` command that ran elevated |

## Scope

- One host. The bypass only elevates within the same user's context, so the
  account that ran it is the one to treat as compromised, now with high-integrity
  code execution on WORKSTATION5.
- From a high-integrity process the attacker can install services, dump LSASS,
  tamper with defences and persist. Assume those are possible next steps and
  hunt for them on the host.

## Containment, eradication, recovery

1. **Contain:** isolate the host, kill the elevated PowerShell tree.
2. **Eradicate:** delete the hijack keys under
   `HKCU\Software\Classes\ms-settings\shell\open\command` (they are left behind
   by this technique), and find and remove the Empire agent that drove it.
3. **Recover:** reset the credentials of the account involved, review what the
   elevated session did (services, scheduled tasks, other persistence), and
   rebuild if the high-integrity window was long. Application control
   (WDAC / AppLocker) and the "always notify" UAC level reduce exposure to this
   class of bypass.

## Tuning notes

- The HKCU `Classes\...\shell\open\command` keys for auto-elevating handlers
  are essentially never written by legitimate software, so this rule needs no
  exclusions and is high confidence. The four hits are the key creation, the
  `DelegateExecute` write, the `(Default)` write, and a repeat of the sequence
  a few seconds later (the atomic ran twice in the capture).
- The same pattern covers the sdclt and eventvwr variants because the rule
  matches `\Folder\shell\open\command`, `\mscfile\shell\open\command` and
  `\exefile\shell\open\command` as well as `ms-settings`. Those variants were
  not in this dataset, so they are covered by rule logic but not yet by a real
  fixture; noted as a gap to fill when a suitable public capture is found.
