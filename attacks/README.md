# Attack simulation plan

Each row is one technique to simulate in the lab, the Atomic Red Team test that
exercises it, the telemetry it should produce, and the rule in `detections/`
that should fire. Until the lab is built, every rule is tested against the
public dataset in the last column instead (see `data/README.md`).

Atomic Red Team test numbers change when tests are added upstream; the GUIDs do
not. Both were checked against `redcanaryco/atomic-red-team` master on
2026-09-22.

## Windows (WIN-EP01)

| # | ATT&CK | Atomic test | Expected telemetry | Rule | Public dataset used for now |
|---|---|---|---|---|---|
| W1 | T1003.001 LSASS Memory | T1003.001 #2 Dump LSASS.exe Memory using comsvcs.dll (`2536dee2-12fb-459a-8c37-971844fa73be`) | Sysmon 1: `rundll32.exe ... comsvcs.dll MiniDump <pid> ...`; Sysmon 10 on lsass | `win_proc_lsass_dump_comsvcs` | OTRF `psh_lsass_memory_dump_comsvcs`, OTRF `LSASS_campaign_03` |
| W2 | T1003.003 NTDS | T1003.003 #1 Create Volume Shadow Copy with vssadmin (`dcebead7-6c28-4b4b-bf3c-79deb1b1fc7f`), #3 Dump Active Directory Database with NTDSUtil (`2364e33d-ceab-4641-8468-bfb1d7cc2723`, needs a DC) | Sysmon 1: `vssadmin create shadow`, `ntdsutil "ac i ntds" "ifm" ...` | `win_proc_ntds_dump_ntdsutil_vssadmin` | OTRF `cmd_dumping_ntds_dit_file_ntdsutil`, `cmd_dumping_ntds_dit_file_volume_shadow_copy` |
| W3 | T1003.002 Security Account Manager | T1003.002 #1 Registry dump of SAM, creds, and secrets (`5c2571d0-1572-416d-9676-812e64ca9f44`) | Sysmon 1: `reg save HKLM\sam ...` | `win_proc_reg_save_credential_hives` | OTRF `empire_shell_reg_dump_sam` |
| W4 | T1218.005 Mshta | T1218.005 #1 JavaScript scheme with GetObject (`1483fab9-4f52-4217-a9ce-daa9d7747cae`), #2 VBScript to execute command (`906865c3-e05f-4acc-85c4-fbc185455095`) | Sysmon 1: `mshta.exe javascript:...` / `vbscript:...` | `win_proc_mshta_inline_script` | OTRF `cmd_mshta_javascript_getobject_sct`, `cmd_mshta_vbscript_execute_psh` |
| W5 | T1218.010 Regsvr32 | T1218.010 #1 local COM scriptlet (`449aa403-6aba-47ce-8a37-247d21ef0306`), #2 remote COM scriptlet (`c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36`) | Sysmon 1: `regsvr32 /s /u /i:<sct> scrobj.dll` | `win_proc_regsvr32_scriptlet` | OTRF `empire_launcher_sct_regsvr32` |
| W6 | T1059.001 PowerShell | T1059.001 #17 PowerShell Command Execution (`a538de64-1c74-46ed-aa60-b995ed302598`) | Sysmon 1: `powershell.exe -e <base64>` | `win_proc_powershell_encoded_command` | OTRF Empire datasets (launcher command lines) |
| W7 | T1547.001 Registry Run Keys | T1547.001 #1 Reg Key Run (`e55be3fd-3521-4610-9d1a-e210e42dcf05`) | Sysmon 13: value under `...\CurrentVersion\Run\` | `win_reg_run_key_suspicious_value` | OTRF `empire_persistence_registry_modification_run_keys_standard_user` |
| W8 | T1548.002 Bypass UAC | T1548.002 #3 Fodhelper (`58f641ea-12e3-499a-b684-44dee46bd182`), #7 sdclt DelegateExecute (`3be891eb-4608-4173-87e8-78b494c029b7`) | Sysmon 13: `...\ms-settings\shell\open\command` or `...\Folder\shell\open\command` | `win_reg_uac_bypass_shell_open_command` | OTRF `empire_uac_shellapi_fodhelper` |
| W9 | T1546.003 WMI Event Subscription | T1546.003 #1 CommandLineEventConsumer (`3c64f177-28e2-49eb-a799-d767b24dd1e0`) | Sysmon 19, 20, 21 | `win_wmi_commandline_event_consumer` | OTRF `empire_wmi_local_event_subscriptions_elevated_user` |
| W10 | T1543.003 Windows Service, T1569.002 Service Execution | T1569.002 #1 Execute a Command as a Service (`2382dee2-a75f-49aa-9378-f52df6ed3fb1`), T1543.003 #2 Service Installation CMD (`981e2942-e433-44e9-afc1-8c957a1496b6`) | System 7045 with a shell in `ImagePath` | `win_system_service_install_shell_imagepath` | OTRF `empire_psexec_dcerpc_tcp_svcctl`, `empire_smbexec_dcerpc_smb_svcctl` |
| W11 | T1053.005 Scheduled Task | T1053.005 #7 Scheduled Task Executing Base64 Encoded Commands From Registry (`e895677d-4f06-49ab-91b6-ae3742d0a2ba`) | Sysmon 1: `schtasks /create ... /tr "...powershell..."`; Security 4698 | `win_proc_schtasks_create_script_host` | OTRF `empire_schtasks_creation_standard_user` |

## Linux (UBU-SRV01)

| # | ATT&CK | Atomic test | Expected telemetry | Rule | Public dataset used for now |
|---|---|---|---|---|---|
| L1 | T1190 Exploit Public-Facing Application, T1059.004 Unix Shell | none in Atomic Red Team; use the Java emulation below, or a deliberately vulnerable app (Log4Shell, Spring4Shell) in a throwaway VM | Sysmon for Linux 1: shell whose parent is `java` | `lnx_proc_shell_spawned_by_java` | OTRF `Log4Shell` (syslog Sysmon), Splunk `T1190/spring4shell` |
| L2 | T1105 Ingress Tool Transfer, T1059.004 | T1059.004 #12 Detecting pipe-to-shell (`fca246a8-a585-4f28-a2df-6495973976a1`), T1105 #27 Linux Download File and Run (`bdc373c5-e9cf-4563-8a7b-a9ba720a90f3`) | Sysmon for Linux 1: `curl ... \| bash` | `lnx_proc_download_piped_to_shell` | Splunk `T1105/atomic_red_team` (curl/wget) |
| L3 | T1059.004 Unix Shell (reverse shell) | none that matches exactly; use the `/dev/tcp` emulation below | Sysmon for Linux 3: network connection made by `bash` | `lnx_net_shell_outbound_connection` | OTRF `Log4Shell` (syslog Sysmon) |
| L4 | T1505.003 Web Shell | T1505.003 #1 is Windows only; use the Java emulation below | Sysmon for Linux 11: `.jsp` created by `java` under `webapps/` | `lnx_file_jsp_written_by_java` | Splunk `T1190/spring4shell` |
| L5 | T1098.004 SSH Authorized Keys | T1098.004 #1 Modify SSH Authorized Keys (`342cc723-127c-4d3a-8292-9c0c6b4ecadc`) | Sysmon for Linux 11 on `~/.ssh/authorized_keys`; auditd watch `ssh_keys` | `lnx_file_ssh_authorized_keys_write` | Splunk `T1098.004/ssh_authorized_keys` |
| L6 | T1136.001 Local Account | T1136.001 #1 Create a user account on a Linux system (`40d8eabd-e394-46f6-8785-b9bfa1d011d2`) | auditd `EXECVE` / `PROCTITLE` for `useradd` | `lnx_auditd_useradd` | Splunk `T1136.001/linux_auditd_add_user` |
| L7 | T1140 Deobfuscate/Decode | T1140 #5 Base64 decoding with shell utilities (`b4f6a567-a27a-41e5-b8ef-ac4b4008bb7e`) | auditd `EXECVE` with `a0=base64 a1=-d` | `lnx_auditd_base64_decode` | Splunk `T1140/linux_auditd_base64` |

## How to run a test in the lab

Atomic Red Team via Invoke-AtomicRedTeam (https://github.com/redcanaryco/invoke-atomicredteam),
on a snapshot of WIN-EP01 with the NAT adapter disconnected unless the test
needs to download its prerequisites:

```
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be -ShowDetails
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be -GetPrereqs
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be
Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be -Cleanup
```

Write down the start and end time of each run, export the events for that
window (`lab/SETUP.md`, section 5), run `soclab run`, and revert the snapshot.
A test counts as detected only if the expected rule fires inside the window;
note any other rules that fire as well.

## Lab emulation scripts

`emulation/` holds small scripts that produce the same telemetry as the rows
above without doing the harmful part, for a first pass before installing Atomic
Red Team. They have not been run in this repo (no Windows host, and no root on
the build machine for the Linux parts); run them only inside the lab VMs.

- `emulation/windows/Invoke-SocLabEmulation.ps1`: W1 to W11. For example, W1
  runs the comsvcs `MiniDump` export against a `notepad.exe` it started itself
  rather than lsass, W3 saves only the `SYSTEM` hive, and every registry key,
  task, service and WMI object it creates is removed again.
- `emulation/linux/soclab-emulation.sh`: L1 to L7, with the Java parts in
  `SocLabJava.java` (a single-file program for `java SocLabJava.java`). The
  "download" is from a Python web server it starts on 127.0.0.1, and the
  reverse shell connection is a plain TCP connect to an address you choose.
