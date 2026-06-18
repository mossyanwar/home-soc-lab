# Fixture sources

Every file here is a handful of events extracted from a public dataset,
kept small and used only by the tests. Licences: OTRF Security-Datasets is
MIT, splunk/attack_data is Apache-2.0; both allow redistribution with
attribution. See `../../data/README.md`.

| Fixture | Extracted from |
|---|---|
| `linux/auditd_benign.log` | splunk attack_data T1136.001/linux_auditd_add_user/auditd_proctitle_user_add.log (grep hunting lines, not useradd) |
| `linux/file_benign.log` | splunk attack_data T1190/spring4shell/java_write_jsp-linux-sysmon.log (non-jsp writes) |
| `linux/lnx_auditd_base64_decode.attack.log` | splunk attack_data T1140/linux_auditd_base64/auditd_execve_base64.log |
| `linux/lnx_auditd_useradd.attack.log` | splunk attack_data T1136.001/linux_auditd_add_user/linux_auditd_add_user.log |
| `linux/lnx_file_jsp_written_by_java.attack.log` | splunk attack_data T1190/spring4shell/java_write_jsp-linux-sysmon.log |
| `linux/lnx_file_ssh_authorized_keys_write.attack.log` | splunk attack_data T1098.004/ssh_authorized_keys/authkey_linux-sysmon.log |
| `linux/lnx_net_shell_outbound_connection.attack.json` | OTRF compound/Log4Shell/syslog_sysmon_log4shell_cve2021_44228_jndi_reference |
| `linux/lnx_proc_download_piped_to_shell.attack.log` | splunk attack_data T1105/atomic_red_team/linux-sysmon_curlwget.log |
| `linux/lnx_proc_shell_spawned_by_java.attack.log` | splunk attack_data T1190/spring4shell/java_write_jsp-linux-sysmon.log |
| `linux/network_benign.json` | OTRF compound/Log4Shell/syslog_sysmon_log4shell... (non-attack connections) |
| `linux/process_creation_benign.log` | splunk attack_data T1190/spring4shell/java_write_jsp-linux-sysmon.log (non-attack events) |
| `windows/process_creation_benign.jsonl` | OTRF atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil (non-attack events) |
| `windows/registry_benign.jsonl` | OTRF atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user (non-attack events) |
| `windows/system_benign.jsonl` | OTRF atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl (non-7045 System events) |
| `windows/win_proc_bitsadmin_transfer.attack.jsonl` | OTRF atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script |
| `windows/win_proc_lsass_dump_comsvcs.attack.jsonl` | OTRF atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs |
| `windows/win_proc_mshta_inline_script.attack.jsonl` | OTRF atomic/windows/defense_evasion/host/cmd_mshta_javascript_getobject_sct |
| `windows/win_proc_ntds_dump.attack.jsonl` | OTRF atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil and .../cmd_dumping_ntds_dit_file_volume_shadow_copy |
| `windows/win_proc_powershell_encoded_command.attack.jsonl` | OTRF atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32 |
| `windows/win_proc_reg_save_credential_hives.attack.jsonl` | OTRF atomic/windows/credential_access/host/empire_shell_reg_dump_sam |
| `windows/win_proc_regsvr32_scriptlet.attack.jsonl` | OTRF atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32 |
| `windows/win_proc_schtasks_create_script_host.attack.jsonl` | OTRF atomic/windows/persistence/host/empire_schtasks_creation_standard_user |
| `windows/win_reg_run_key_script_host.attack.jsonl` | OTRF atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user |
| `windows/win_reg_uac_bypass_shell_open_command.attack.jsonl` | OTRF atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper |
| `windows/win_system_service_install_script_host.attack.jsonl` | OTRF atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl |
| `windows/win_wmi_commandline_event_consumer.attack.jsonl` | OTRF atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user |
| `windows/wmi_benign.jsonl` | OTRF atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user (WmiFilter/WmiBinding events) |
