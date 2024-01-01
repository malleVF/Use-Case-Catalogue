---
title: "Sysinternals PsService Execution"
status: "experimental"
created: "2022/06/16"
last_modified: "2023/02/24"
tags: [discovery, persistence, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Sysinternals PsService Execution

### Description

Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering

```yml
title: Sysinternals PsService Execution
id: 3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f
status: experimental
description: Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psservice
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/16
modified: 2023/02/24
tags:
    - attack.discovery
    - attack.persistence
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'psservice.exe'
        - Image|endswith:
              - '\PsService.exe'
              - '\PsService64.exe'
    condition: selection
falsepositives:
    - Legitimate use of PsService by an administrator
level: medium

```