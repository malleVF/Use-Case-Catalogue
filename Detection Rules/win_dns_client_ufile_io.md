---
title: "DNS Query To Ufile.io - DNS Client"
status: "experimental"
created: "2023/01/16"
last_modified: "2023/09/18"
tags: [exfiltration, t1567_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "dns-client"
level: "low"
---

## DNS Query To Ufile.io - DNS Client

### Description

Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration

```yml
title: DNS Query To Ufile.io - DNS Client
id: 090ffaad-c01a-4879-850c-6d57da98452d
related:
    - id: 1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b
      type: similar
status: experimental
description: Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/16
modified: 2023/09/18
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    service: dns-client
    definition: 'Requirements: Microsoft-Windows-DNS Client Events/Operational Event Log must be enabled/collected in order to receive the events.'
detection:
    selection:
        EventID: 3008
        QueryName|contains: 'ufile.io'
    condition: selection
falsepositives:
    - DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take
level: low

```
