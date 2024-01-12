---
created: 2017-05-31
last_modified: 2023-10-03
version: 2.3
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1105
platforms: Linux, Windows, macOS
tags: [T1105, techniques, Command_and_Control]
---

## Ingress Tool Transfer

### Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). 

On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)

Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts.

Files can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016) In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.(Citation: Dropbox Malware Sync)

### Detection

Monitor for file creation and files transferred into the network. Unusual processes with external network connections creating files on-system may be suspicious. Use of utilities, such as [ftp](https://attack.mitre.org/software/S0095), that does not normally occur may also be suspicious.

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Specifically, for the finger utility on Windows and Linux systems, monitor command line or terminal execution for the finger command. Monitor network activity for TCP port 79, which is used by the finger utility, and Windows <code>netsh interface portproxy</code> modifications to well-known ports such as 80 and 443. Furthermore, monitor file system for the download/creation and execution of suspicious files, which may indicate adversary-downloaded payloads. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```query
tag: detection_rule
tag: T1105
```

### Rule Testing

```query
tag: atomic_test
tag: T1105
```
