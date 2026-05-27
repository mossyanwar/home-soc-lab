# Lab architecture

The lab is three virtual machines on an isolated network, plus the analysis
tooling in this repo. It is designed to run on one desktop with 32 GB of RAM
(16 GB works if the SIEM heap is cut to 1 GB and only one endpoint runs at a time).

This repo contains the configuration for the lab, but the lab itself was not
built or run while writing it; the detection results in `reports/` come from
public datasets recorded in other people's labs (see `data/README.md`).

## Hosts

| Host | OS | Role | Telemetry |
|---|---|---|---|
| `WIN-EP01` | Windows 10/11 Pro (evaluation ISO is fine) | User endpoint, target for Windows atomics | Sysmon (config in `windows/sysmon-config.xml`), Security log with advanced audit policy and command line in 4688, PowerShell script block logging, System log |
| `UBU-SRV01` | Ubuntu Server 22.04 or 24.04 LTS | SSH server and small web app host, target for Linux atomics | auditd (rules in `linux/audit.rules`), Sysmon for Linux (`linux/sysmon-linux.xml`), sshd auth logs via journald |
| `SIEM01` | Ubuntu Server 24.04 with Docker | Elasticsearch and Kibana, single node | n/a |

No separate attacker VM is needed for the first phase: Atomic Red Team tests run
locally on each target. A Kali VM can be added later for SSH brute force and
lateral movement tests.

## Network

- One internal (host-only) network, `10.10.50.0/24`, with no route to the home LAN.
- `SIEM01` 10.10.50.10, `WIN-EP01` 10.10.50.20, `UBU-SRV01` 10.10.50.30.
- A second NAT adapter on each VM is enabled only for installing updates and
  tools, and disconnected before running any attack simulation.
- Elasticsearch (9200) and Kibana (5601) bind to the internal address only.

## Data flow

```mermaid
flowchart LR
  subgraph WIN["WIN-EP01 (Windows)"]
    S1[Sysmon] --> EL[Windows event logs]
    SEC[Security / System / PowerShell] --> EL
    EL --> WLB[Winlogbeat]
    EL -. export-events.ps1 .-> J1[JSONL export]
  end
  subgraph LNX["UBU-SRV01 (Ubuntu)"]
    AU[auditd] --> AL[/var/log/audit/audit.log/]
    SL[Sysmon for Linux] --> JD[journald / syslog]
    SSHD[sshd] --> JD
    AL --> FB[Filebeat]
    JD --> FB
  end
  subgraph SIEM["SIEM01"]
    ES[(Elasticsearch)] --> KB[Kibana]
  end
  WLB -- TLS 9200 --> ES
  FB -- TLS 9200 --> ES
  subgraph REPO["this repo"]
    R[Sigma rules] --> C[pySigma conversion] --> KB
    R --> E[soclab engine]
    J1 --> E
    AL -. copy .-> E
    JD -. copy .-> E
  end
```

There are two ways to run the detections:

1. In the SIEM. `soclab convert` turns each Sigma rule into a Lucene query
   (ECS field names, for Kibana) or Splunk SPL. These can be loaded as Kibana
   saved searches or detection rules.
2. Offline with the engine in this repo. Windows events are exported to JSONL
   with `windows/export-events.ps1`; on Linux, `audit.log` and the Sysmon syslog
   lines are copied off the box and normalised with `soclab normalise`. This is
   the path used for the public datasets, and it does not need the SIEM at all.

## Why these choices

- **Sysmon** gives process, registry, WMI, network and file events with parent
  process context, which the Security log alone does not. Most public detection
  content (SigmaHQ, the OTRF datasets) assumes it.
- **auditd** is already on Ubuntu, records every `execve` with full arguments
  when told to, and its raw log is easy to ship or copy. **Sysmon for Linux**
  adds parent process and network connection context in the same schema as
  Windows Sysmon, which keeps the Sigma field names the same on both platforms.
- **Elasticsearch and Kibana** run on a single node with a free basic licence,
  and pySigma has a maintained Elasticsearch backend. Wazuh would also work and
  ships its own agent; I chose Elastic because the converted queries can be
  pasted straight into Kibana.
- **One internal network** keeps the attack simulations off the home LAN. The
  atomics in `attacks/` are benign, but some Atomic Red Team tests download
  tools, so updates and attack runs are never done with the NAT adapter up.

## Log sources and what they are used for

| Source | Events used by rules in `detections/` |
|---|---|
| Sysmon (Windows) | 1 process creation, 12/13 registry, 19/20/21 WMI subscription |
| System log | 7045 service installed |
| Sysmon for Linux | 1 process creation, 3 network connection, 11 file create |
| auditd | `EXECVE`, `PROCTITLE` records |

Security 4688, PowerShell 4104 and sshd logs are collected but not yet used by
any rule. They are listed in the next steps in the top-level README.
