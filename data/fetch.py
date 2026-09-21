#!/usr/bin/env python3
"""Download the public attack datasets the rules and write-ups use.

Only the specific files this project references are fetched, not the whole
repositories. Large data is written under data/raw/ (zips, LFS blobs) and
data/events/ (unzipped JSON), both of which are gitignored.

    python3 data/fetch.py --list
    python3 data/fetch.py windows-core
    python3 data/fetch.py all

No third-party Python packages are needed; this uses urllib from the standard
library. Run it with -I so it cannot import anything from the download
directories:  python3 -I data/fetch.py all
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")
EVENTS = os.path.join(HERE, "events")

OTRF = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/"
# The media.* host serves Git LFS blobs for splunk/attack_data without git-lfs.
SPLUNK = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/"

# group -> list of (source, path). source is "otrf-zip", "otrf-raw" or "splunk".
GROUPS: dict[str, list[tuple[str, str]]] = {
    "windows-core": [
        ("otrf-zip", "atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip"),
        ("otrf-zip", "compound/LSASS_campaign_03/metasploit_comsvcs_lsass_memory_dump.zip"),
        ("otrf-zip", "atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip"),
        ("otrf-zip", "atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy.zip"),
        ("otrf-zip", "atomic/windows/credential_access/host/empire_shell_reg_dump_sam.zip"),
        ("otrf-zip", "atomic/windows/defense_evasion/host/cmd_mshta_javascript_getobject_sct.zip"),
        ("otrf-zip", "atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip"),
        ("otrf-zip", "atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32.zip"),
        ("otrf-zip", "atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip"),
    ],
    "windows-persistence": [
        ("otrf-zip", "atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip"),
        ("otrf-zip", "atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper.zip"),
        ("otrf-zip", "atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip"),
        ("otrf-zip", "atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip"),
        ("otrf-zip", "atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip"),
        ("otrf-zip", "atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip"),
    ],
    "linux": [
        ("otrf-zip", "compound/Log4Shell/syslog_sysmon_log4shell_cve2021_44228_jndi_reference.zip"),
        ("splunk", "T1190/spring4shell/java_write_jsp-linux-sysmon.log"),
        ("splunk", "T1105/atomic_red_team/linux-sysmon_curlwget.log"),
        ("splunk", "T1098.004/ssh_authorized_keys/authkey_linux-sysmon.log"),
        ("splunk", "T1136.001/linux_auditd_add_user/linux_auditd_add_user.log"),
        ("splunk", "T1136.001/linux_auditd_add_user/auditd_proctitle_user_add.log"),
        ("splunk", "T1140/linux_auditd_base64/auditd_execve_base64.log"),
    ],
}


def _download(url: str, dest: str) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print(f"  GET {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "soclab-fetch"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        while chunk := resp.read(1 << 16):
            fh.write(chunk)


def _fetch_item(source: str, path: str) -> None:
    name = os.path.basename(path)
    if source == "otrf-zip":
        dest = os.path.join(RAW, "otrf", name)
        _download(OTRF + path, dest)
        with zipfile.ZipFile(dest) as zf:
            os.makedirs(EVENTS, exist_ok=True)
            for member in zf.namelist():
                if member.endswith("/"):
                    continue
                target = os.path.join(EVENTS, os.path.basename(member))
                with zf.open(member) as src, open(target, "wb") as out:
                    out.write(src.read())
                print(f"    -> events/{os.path.basename(member)}")
    elif source == "splunk":
        dest = os.path.join(EVENTS, path.replace("/", "__"))
        _download(SPLUNK + path, dest)
        print(f"    -> events/{os.path.basename(dest)}")
    else:
        raise ValueError(f"unknown source {source}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("groups", nargs="*", help="group name(s), or 'all'")
    parser.add_argument("--list", action="store_true", help="list groups and exit")
    args = parser.parse_args(argv)

    if args.list or not args.groups:
        print("groups:")
        for name, items in GROUPS.items():
            print(f"  {name:22} {len(items)} file(s)")
        print("  all                    every group")
        return 0

    names = list(GROUPS) if args.groups == ["all"] else args.groups
    for name in names:
        if name not in GROUPS:
            print(f"unknown group '{name}' (try --list)", file=sys.stderr)
            return 2
        print(f"[{name}]")
        for source, path in GROUPS[name]:
            try:
                _fetch_item(source, path)
            except Exception as exc:  # keep going; report at the end
                print(f"    failed: {exc}", file=sys.stderr)
    print(f"\ndone. events are in {EVENTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
