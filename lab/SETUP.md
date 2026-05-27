# Lab setup guide

Step-by-step build for the lab described in `architecture.md`. I wrote this
from the vendor documentation and have not run it end to end; there was no
hypervisor or Docker daemon on the machine this repo was built on. Treat each
step as a checklist to verify, and check the linked docs for the versions you
install.

## 0. Host and network

1. Hypervisor: VirtualBox 7, Hyper-V or Proxmox. 32 GB RAM is comfortable,
   16 GB works with the SIEM heap set to 1 GB.
2. Create an internal / host-only network `10.10.50.0/24` with DHCP off.
3. Give each VM two adapters: the internal one with a static address, and a NAT
   adapter that you connect only for updates and installs.

| VM | vCPU | RAM | Disk | Address |
|---|---|---|---|---|
| SIEM01 | 2 | 6 GB | 80 GB | 10.10.50.10 |
| WIN-EP01 | 2 | 4 GB | 60 GB | 10.10.50.20 |
| UBU-SRV01 | 1 | 2 GB | 30 GB | 10.10.50.30 |

## 1. SIEM01 (Elasticsearch and Kibana)

1. Install Ubuntu Server 24.04 and Docker Engine with the compose plugin
   (https://docs.docker.com/engine/install/ubuntu/).
2. Raise the mmap limit Elasticsearch needs and make it persistent:
   ```
   echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf
   sudo sysctl --system
   ```
3. Copy `lab/siem/` to the VM, then:
   ```
   cd siem
   cp .env.example .env      # set ELASTIC_PASSWORD, KIBANA_PASSWORD, KIBANA_ENCRYPTION_KEY
   docker compose up -d
   docker compose ps         # wait until es01 and kibana are healthy
   docker compose cp es01:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt
   ```
4. Create a least-privilege role and user for the shippers, so the `elastic`
   superuser password never goes onto the endpoints:
   ```
   export ES=https://10.10.50.10:9200
   curl --cacert ca.crt -u "elastic:$ELASTIC_PASSWORD" -X PUT "$ES/_security/role/soclab_shipper" \
     -H 'Content-Type: application/json' -d '{
       "cluster": ["monitor", "read_ilm", "read_pipeline"],
       "indices": [{"names": ["winlogbeat-*", "filebeat-*"],
                    "privileges": ["create_doc", "view_index_metadata", "auto_configure"]}]
     }'
   curl --cacert ca.crt -u "elastic:$ELASTIC_PASSWORD" -X PUT "$ES/_security/user/soclab_shipper" \
     -H 'Content-Type: application/json' -d '{"password": "<shipper password>", "roles": ["soclab_shipper"]}'
   ```
5. Open Kibana at `https://10.10.50.10:5601` from a browser on the lab network
   and log in as `elastic`.

## 2. WIN-EP01 (Windows endpoint)

1. Install Windows 10 or 11 Pro, set the static address, apply updates, then
   disconnect the NAT adapter.
2. Sysmon (https://learn.microsoft.com/sysinternals/downloads/sysmon):
   ```
   sysmon64.exe -accepteula -i lab\windows\sysmon-config.xml
   sysmon64.exe -c            # prints the loaded config
   ```
3. Audit policy, command line logging and PowerShell logging, from an elevated
   PowerShell prompt:
   ```
   Set-ExecutionPolicy -Scope Process Bypass
   .\lab\windows\audit-policy.ps1
   ```
4. Winlogbeat (https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-installation-configuration.html):
   unzip to `C:\Program Files\Winlogbeat`, copy `lab\windows\winlogbeat.yml`
   over the default config, copy `ca.crt` to `C:\ProgramData\winlogbeat\`,
   add `SHIPPER_PASSWORD` to the keystore, then run the one-off setup as
   `elastic` so the index templates and ingest pipelines are loaded:
   ```
   .\winlogbeat.exe setup --index-management --pipelines -E output.elasticsearch.username=elastic -E output.elasticsearch.password=<elastic password>
   .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   ```
5. Take a VM snapshot called `baseline`. Every attack run starts from it.

## 3. UBU-SRV01 (Ubuntu server)

1. Install Ubuntu Server 22.04 or 24.04 with OpenSSH, set the static address.
2. auditd:
   ```
   sudo apt install auditd
   sudo cp lab/linux/audit.rules /etc/audit/rules.d/50-soclab.rules
   # edit the per-user ~/.ssh watch to match your account name
   sudo augenrules --load
   sudo auditctl -l | head
   ```
3. Sysmon for Linux (https://github.com/microsoft/SysmonForLinux, packages
   from packages.microsoft.com):
   ```
   sudo apt install sysmonforlinux
   sudo sysmon -accepteula -i lab/linux/sysmon-linux.xml
   journalctl -t sysmon -n 5 -o cat     # one XML event per line
   ```
4. Filebeat from the Elastic apt repository, then:
   ```
   sudo cp lab/linux/filebeat.yml /etc/filebeat/filebeat.yml
   sudo cp ca.crt /etc/filebeat/ca.crt
   sudo filebeat keystore create && sudo filebeat keystore add SHIPPER_PASSWORD
   sudo filebeat setup --index-management --pipelines --modules auditd,system \
     -E output.elasticsearch.username=elastic -E output.elasticsearch.password=<elastic password>
   sudo systemctl enable --now filebeat
   ```
5. Snapshot as `baseline`.

## 4. Check the pipeline

- Windows: run `whoami /groups` and look for a Sysmon event 1 with that command
  line in Kibana Discover (`winlogbeat-*`).
- Linux: run `id` and look for an auditd `EXECVE` record (`filebeat-*`), and a
  Sysmon event 1 from the `sysmon-linux` input.

If either is missing, check the shipper logs before going further; a silent
pipeline is the most common way a home lab produces false negatives.

## 5. Running the detections

Offline, with the engine in this repo (no SIEM needed):

```
# on WIN-EP01, after an attack run
.\lab\windows\export-events.ps1 -Since (Get-Date).AddMinutes(-30) -OutFile C:\lab\run1.jsonl

# on UBU-SRV01
sudo cp /var/log/audit/audit.log ~/run1-audit.log
journalctl -t sysmon -o cat --since "30 min ago" > ~/run1-sysmon.xml

# on the analysis machine, inside this repo's venv
soclab normalise -f auditd ~/run1-audit.log -o out/run1-audit.jsonl
soclab normalise -f sysmon-xml ~/run1-sysmon.xml -o out/run1-sysmon.jsonl
soclab run --rules detections C:\lab\run1.jsonl out/run1-audit.jsonl out/run1-sysmon.jsonl
```

In Kibana: `soclab convert --target lucene detections` prints one query per
rule using ECS field names for the Windows rules. These can be pasted into
Discover or used as custom query detection rules. The Linux rules use Sysmon
and auditd field names as they appear in the raw logs; Filebeat renames those
fields, so the Linux queries need a pySigma processing pipeline for Filebeat's
schema before they will match in Kibana. That pipeline is not written yet.

## 6. Resetting

Revert both endpoints to `baseline` after each run. Delete old indices in
Kibana (Stack Management, Index Management) if the SIEM disk fills up.
