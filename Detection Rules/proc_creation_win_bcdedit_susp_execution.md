---
title: "Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE"
status: "test"
created: "2019/02/07"
last_modified: "2023/02/15"
tags: [defense_evasion, t1070, persistence, t1542_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE

### Description

Detects potential malicious and unauthorized usage of bcdedit.exe

```yml
title: Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE
id: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
status: test
description: Detects potential malicious and unauthorized usage of bcdedit.exe
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
    - https://twitter.com/malwrhunterteam/status/1372536434125512712/photo/2
author: '@neu5ron'
date: 2019/02/07
modified: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.persistence
    - attack.t1542.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\bcdedit.exe'
        - OriginalFileName: 'bcdedit.exe'
    selection_cli:
        CommandLine|contains:
            - 'delete'
            - 'deletevalue'
            - 'import'
            - 'safeboot'
            - 'network'
    condition: all of selection_*
level: medium

```
