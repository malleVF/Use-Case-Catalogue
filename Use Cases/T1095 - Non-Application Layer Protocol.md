---
created: 2017-05-31
last_modified: 2023-09-29
version: 2.3
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1095
platforms: Linux, Network, Windows, macOS
tags: [T1095, techniques, Command_and_Control]
---

## Non-Application Layer Protocol

### Description

Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).

ICMP communication between hosts is one example.(Citation: Cisco Synful Knock Evolution) Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts.(Citation: Microsoft ICMP) However, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.

### Detection

Analyze network traffic for ICMP messages or other protocols that contain abnormal data or are not normally seen within or exiting the network.(Citation: Cisco Blog Legacy Device Attacks)

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2) 

Monitor and investigate API calls to functions associated with enabling and/or utilizing alternative communication channels.

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1095
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1095
```
