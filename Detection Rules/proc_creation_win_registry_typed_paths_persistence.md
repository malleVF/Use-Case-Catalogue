---
title: "Persistence Via TypedPaths - CommandLine"
status: "test"
created: "2022/08/22"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Persistence Via TypedPaths - CommandLine

### Description

Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt

```yml
title: Persistence Via TypedPaths - CommandLine
id: ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba
status: test
description: Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt
references:
    - https://twitter.com/dez_/status/1560101453150257154
    - https://forensafe.com/blogs/typedpaths.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/22
tags:
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
