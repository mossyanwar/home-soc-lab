# Incident 2: AD database theft via shadow copy

**Dataset:** OTRF Security-Datasets,
`datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy`
(MIT licence).
**Host:** DC01.pandalab.com (domain controller).
**Analysed with:** `soclab run --rules detections cmd_dumping_ntds_dit_file_volume_shadow_copy.json`
over 16,843 events.

## Summary

On a domain controller, an operator created a volume shadow copy and then
exported the `SYSTEM` registry hive. This is the standard way to steal the
Active Directory database (`ntds.dit`) off a live DC: the shadow copy gives a
readable copy of the locked `ntds.dit`, and the `SYSTEM` hive carries the boot
key needed to decrypt the password hashes inside it. The engine raised two
detections, one per step.

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 19:20:48 | **Shadow copy** | `cmd.exe` -> `vssadmin.exe create shadow /for=C:` |
| 19:24:02 | **Hive export** | `cmd.exe` -> `reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE` |

The two steps are about three and a half minutes apart, both from `cmd.exe` on
DC01. In a real intrusion the copy of `ntds.dit` out of the shadow copy would
sit between or just after these; the DC role plus these two commands together
is already a high-confidence AD-theft signal.

## Rules that fired

```
[high] Active Directory database dump via ntdsutil or shadow copy
    vssadmin.exe  create shadow /for=C:
    (Sysmon event 1, 2023-07-19 19:20:48)

[high] Registry hive export of SAM, SYSTEM or SECURITY
    reg  save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE
    (Sysmon event 1, 2023-07-19 19:24:02)
```

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1003.003 OS Credential Dumping: NTDS | shadow copy of C: on a DC |
| Credential Access | T1003.002 OS Credential Dumping: Security Account Manager | `reg save HKLM\SYSTEM` (boot key for ntds.dit) |

The `reg save HKLM\SYSTEM` maps to T1003.002 in the rule because that is the
rule that owns registry-hive export; in this context the SYSTEM hive is being
taken for its boot key to go with `ntds.dit` (T1003.003), not for local SAM
hashes. Worth stating plainly in the ticket so the analyst reads the two hits
as one AD-theft action.

## Scope

- One host, a domain controller. If `ntds.dit` was successfully copied out of
  the shadow copy (the likely next step), **every domain account's password
  hash is compromised**, including `krbtgt`.
- Treat this as a domain-wide credential incident until proven otherwise.

## Containment, eradication, recovery

1. **Contain:** isolate DC01. Identify the logon session that ran the two
   commands (`cmd.exe` parent, the account and logon id from Security 4624 /
   4688 around 19:20) and disable that account.
2. **Eradicate:** delete the shadow copy (`vssadmin delete shadows`) and the
   `C:\Windows\Temp\SYSTEM_HIVE` file and any `ntds.dit` copy. Find how the
   operator got code execution on the DC and close it.
3. **Recover:** this is the serious one. If `ntds.dit` left the DC, perform a
   domain-wide password reset and a **double `krbtgt` reset**, following
   Microsoft's guidance, because stolen hashes allow golden-ticket forgery.
   Rotate the DC machine account. Review DC logon rights so fewer accounts can
   run commands there.

## Tuning notes

- `vssadmin create shadow` has a genuine false-positive source: backup
  software. The rule is scoped by command shape, not host, so on a real
  deployment the vssadmin branch should be narrowed to domain controllers
  (where interactive shadow-copy creation is rare) or the backup service
  account should be excluded. The rule's own false-positive note says this.
- `reg save HKLM\SYSTEM` alone is sometimes legitimate (administrators back up
  the hive). It is the **pairing** with the shadow copy on a DC, inside a few
  minutes, that makes this high confidence. A correlation rule that fires only
  when both appear on the same host in a short window would cut the standalone
  noise; the two single rules here are the building blocks for it.
