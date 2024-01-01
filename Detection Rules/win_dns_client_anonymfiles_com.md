---
title: "DNS Query for Anonfiles.com Domain - DNS Client"
status: "test"
created: "2023/01/16"
last_modified: ""
tags: [exfiltration, t1567_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "dns-client"
level: "high"
---

## DNS Query for Anonfiles.com Domain - DNS Client

### Description

Detects DNS queries for anonfiles.com, which is an anonymous file upload platform often used for malicious purposes

```yml
title: DNS Query for Anonfiles.com Domain - DNS Client
id: 29f171d7-aa47-42c7-9c7b-3c87938164d9
related:
    - id: 065cceea-77ec-4030-9052-fc0affea7110
      type: similar
status: test
description: Detects DNS queries for anonfiles.com, which is an anonymous file upload platform often used for malicious purposes
references:
    - https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/16
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
        QueryName|contains: '.anonfiles.com'
    condition: selection
falsepositives:
    - Rare legitimate access to anonfiles.com
level: high

```
