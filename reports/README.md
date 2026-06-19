# Incident write-ups

Each write-up investigates a real public attack dataset run through this repo's
engine (`soclab run --rules detections <dataset>`). Every event, timestamp,
hostname and rule hit quoted below came from that engine output on that data;
nothing is invented. The dataset is named at the top of each write-up, and
`data/fetch.py` downloads it.

These are not incidents from a running home lab (there is no lab yet). They are
worked as if the recorded telemetry had arrived in the SIEM, to show the
detections and the investigation steps end to end. Timestamps are copied from
the events as recorded; the Sysmon `UtcTime` and the Windows `TimeCreated` in
some OTRF datasets differ by the capture host's timezone offset, and that is
left as-is rather than silently corrected.

| # | Write-up | Dataset | Platform |
|---|---|---|---|
| 1 | [LSASS credential theft after Metasploit access](01_lsass_comsvcs_metasploit.md) | OTRF `LSASS_campaign_03` | Windows |
| 2 | [AD database theft via shadow copy](02_ntds_shadow_copy.md) | OTRF `cmd_dumping_ntds_dit_file_volume_shadow_copy` | Windows |
| 3 | [Log4Shell exploitation and reverse shell](03_log4shell_reverse_shell.md) | OTRF `Log4Shell` (syslog Sysmon) | Linux |
| 4 | [WMI event subscription persistence](04_wmi_event_subscription.md) | OTRF `empire_wmi_local_event_subscriptions_elevated_user` | Windows |
| 5 | [UAC bypass via fodhelper](05_fodhelper_uac_bypass.md) | OTRF `empire_uac_shellapi_fodhelper` | Windows |

Each follows the same shape: summary, dataset, timeline, rules that fired,
ATT&CK mapping, scope, containment / eradication / recovery, and tuning notes.
