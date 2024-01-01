---
title: "Computer System Reconnaissance Via Wmic.EXE"
status: "experimental"
created: "2022/09/08"
last_modified: "2023/02/14"
tags: [discovery, execution, t1047, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Computer System Reconnaissance Via Wmic.EXE

### Description

Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.

```yml
title: Computer System Reconnaissance Via Wmic.EXE
id: 9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f
status: experimental
description: Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/08
modified: 2023/02/14
tags:
    - attack.discovery
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains: 'computersystem'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
