# Incident 4: WMI event subscription persistence

**Dataset:** OTRF Security-Datasets,
`datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user`
(MIT licence).
**Host:** WORKSTATION5.theshire.local (Windows).
**Analysed with:** `soclab run --rules detections <dataset>` over 79,896 events.

## Summary

An Empire agent established fileless persistence by creating a permanent WMI
event subscription named `Updater`: an event filter that fires on a system
uptime condition, a `CommandLineEventConsumer` that runs an encoded PowerShell
command, and a binding tying them together. When the filter later fired, WMI
launched that PowerShell under `WmiPrvSE.exe`. The engine caught both the
subscription being created and the resulting encoded-PowerShell execution.

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 20:43:26.984 | WMI filter created | Sysmon 19, `__EventFilter` name `Updater`, query on `Win32_PerfFormattedData_PerfOS_System` uptime |
| 20:43:27.015 | **Consumer created** | Sysmon 20, `CommandLineEventConsumer` name `Updater`, destination `powershell.exe -NonI -W hidden -enc <base64>` |
| 20:43:27.644 | Binding created | Sysmon 21, `__FilterToConsumerBinding` linking the `Updater` filter and consumer |
| 20:48:37.842 | **Payload runs** | Sysmon 1, `WmiPrvSE.exe` -> `powershell.exe ... -enc <base64>` |

The filter, consumer and binding are the three parts of a permanent WMI
subscription; five minutes later the consumer command actually executes, with
`WmiPrvSE.exe` as its parent, which is the tell-tale sign of WMI-triggered
execution.

## Rules that fired

```
[high]   WMI CommandLineEventConsumer running a script host
    Destination="C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W hidden -enc SQBGACg..."
    (Sysmon event 20, 20:43:27)

[medium] PowerShell encoded command
    ParentImage=C:\Windows\System32\wbem\WmiPrvSE.exe
    CommandLine=... powershell.exe -NonI -W hidden -enc SQBGACg...
    (Sysmon event 1, 20:48:37)
```

The two hits are the same persistence mechanism seen from two angles: the
consumer registration, and the command it later ran. Seeing the encoded
PowerShell with a `WmiPrvSE.exe` parent is strong corroboration on its own.

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence / Privilege Escalation | T1546.003 Event Triggered Execution: WMI Event Subscription | `Updater` filter + CommandLineEventConsumer + binding |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | `-enc` command run by WmiPrvSE |

## Scope

- One host in the data. WMI subscriptions are local to the host unless created
  remotely, so scope is WORKSTATION5 unless the same `Updater` subscription
  appears on others (hunt for the consumer name and the encoded command across
  the fleet).
- The persistence survives reboots and leaves little on disk, so the host
  should be considered compromised until the subscription is removed and the
  initial access is understood.

## Containment, eradication, recovery

1. **Contain:** isolate the host and kill the PowerShell the consumer spawned.
2. **Eradicate:** delete the WMI objects:
   ```
   Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='Updater'" | Remove-WmiObject
   Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='Updater'" | Remove-WmiObject
   Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match 'Updater' } | Remove-WmiObject
   ```
   Then find and remove whatever installed it.
3. **Recover:** decode and analyse the `-enc` payload to learn what it does
   (C2, further persistence) and pivot on those indicators. Reset credentials
   used on the host. Confirm no equivalent subscription remains on peers.

## Tuning notes

- Management products (SCCM, some backup and monitoring agents) create WMI
  consumers legitimately. The rule only fires when the consumer's destination
  command launches a script host or an encoded command, which cuts most benign
  consumers out; the remaining known-good ones should be baselined by consumer
  name.
- The encoded-PowerShell rule firing with a `WmiPrvSE.exe` parent is a useful
  pattern in its own right. A dedicated rule for "script host whose parent is
  WmiPrvSE" would promote this from medium to high without the base64 length
  heuristic; noted as a follow-up.
