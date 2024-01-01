---
created: 2019-09-04
last_modified: 2022-03-08
version: 1.2
tactics: Lateral Movement
url: https://attack.mitre.org/techniques/T1534
platforms: Google Workspace, Linux, Office 365, SaaS, Windows, macOS
tags: [T1534, techniques, Lateral_Movement]
---

## Internal Spearphishing

### Description

Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment. Internal spearphishing is multi-staged campaign where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.(Citation: Trend Micro When Phishing Starts from the Inside 2017)

Adversaries may leverage [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) or [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through [Input Capture](https://attack.mitre.org/techniques/T1056) on sites that mimic email login interfaces.

There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process.(Citation: Trend Micro When Phishing Starts from the Inside 2017) The Syrian Electronic Army (SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the campaign and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users.(Citation: THE FINANCIAL TIMES LTD 2019.)

### Detection

Network intrusion detection systems and email gateways usually do not scan internal email, but an organization can leverage the journaling-based solution which sends a copy of emails to a security service for offline analysis or incorporate service-integrated solutions using on-premise or API-based integrations to help detect internal spearphishing campaigns.(Citation: Trend Micro When Phishing Starts from the Inside 2017)

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1534
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1534
```
