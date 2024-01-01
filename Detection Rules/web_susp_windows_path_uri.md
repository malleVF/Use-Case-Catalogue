---
title: "Suspicious Windows Strings In URI"
status: "test"
created: "2022/06/06"
last_modified: "2023/01/02"
tags: [persistence, exfiltration, t1505_003, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Suspicious Windows Strings In URI

### Description

Detects suspicious Windows strings in URI which could indicate possible exfiltration or webshell communication

```yml
title: Suspicious Windows Strings In URI
id: 9f6a34b4-2688-4eb7-a7f5-e39fef573d0e
status: test
description: Detects suspicious Windows strings in URI which could indicate possible exfiltration or webshell communication
references:
    - https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/06
modified: 2023/01/02
tags:
    - attack.persistence
    - attack.exfiltration
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '=C:/Users'
            - '=C:/Program%20Files'
            - '=C:/Windows'
            - '=C%3A%5CUsers'
            - '=C%3A%5CProgram%20Files'
            - '=C%3A%5CWindows'
    condition: selection
falsepositives:
    - Legitimate application and websites that use windows paths in their URL
level: high

```
