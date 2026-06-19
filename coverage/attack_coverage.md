# ATT&CK coverage

The detections in this repo cover 20 ATT&CK techniques with 19 rules. Each technique below is covered by at least one Sigma rule that has been validated against real attack telemetry (see `reports/` and `tests/`).

| Technique | Name | Tactic(s) | Platform | Rule(s) |
|---|---|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | windows | win_proc_lsass_dump_comsvcs.yml |
| T1003.002 | OS Credential Dumping: Security Account Manager | Credential Access | windows | win_proc_reg_save_credential_hives.yml |
| T1003.003 | OS Credential Dumping: NTDS | Credential Access | windows | win_proc_ntds_dump.yml |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution, Persistence | windows | win_proc_schtasks_create_script_host.yml |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | windows | win_proc_powershell_encoded_command.yml |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Command and Control, Execution, Initial Access | linux | lnx_net_shell_outbound_connection.yml<br>lnx_proc_download_piped_to_shell.yml<br>lnx_proc_shell_spawned_by_java.yml |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence | linux | lnx_file_ssh_authorized_keys_write.yml |
| T1105 | Ingress Tool Transfer | Command and Control, Defense Evasion, Execution | linux, windows | lnx_proc_download_piped_to_shell.yml<br>win_proc_bitsadmin_transfer.yml |
| T1136.001 | Create Account: Local Account | Persistence | linux | lnx_auditd_useradd.yml |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | linux | lnx_auditd_base64_decode.yml |
| T1190 | Exploit Public-Facing Application | Execution, Initial Access | linux | lnx_proc_shell_spawned_by_java.yml |
| T1197 | BITS Jobs | Command and Control, Defense Evasion | windows | win_proc_bitsadmin_transfer.yml |
| T1218.005 | System Binary Proxy Execution: Mshta | Defense Evasion | windows | win_proc_mshta_inline_script.yml |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Defense Evasion | windows | win_proc_regsvr32_scriptlet.yml |
| T1505.003 | Server Software Component: Web Shell | Persistence | linux | lnx_file_jsp_written_by_java.yml |
| T1543.003 | Create or Modify System Process: Windows Service | Execution, Lateral Movement | windows | win_system_service_install_script_host.yml |
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistence, Privilege Escalation | windows | win_wmi_commandline_event_consumer.yml |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence | windows | win_reg_run_key_script_host.yml |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Defense Evasion, Privilege Escalation | windows | win_reg_uac_bypass_shell_open_command.yml |
| T1569.002 | System Services: Service Execution | Execution, Lateral Movement | windows | win_system_service_install_script_host.yml |

## Not covered yet

The lab collects several log sources that no rule uses yet: Windows Security 4688 process creation, PowerShell 4104 script block logs, and Linux sshd authentication logs. These, and the detection gaps called out in the write-ups (a burst of `reg export`, a script host whose parent is `WmiPrvSE.exe`, the sdclt/eventvwr UAC variants), are the obvious next additions. See the top-level README for the full next-steps list.
