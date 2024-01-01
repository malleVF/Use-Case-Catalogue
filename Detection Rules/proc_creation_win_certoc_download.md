---
title: "File Download via CertOC.EXE"
status: "test"
created: "2022/05/16"
last_modified: "2023/10/18"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## File Download via CertOC.EXE

### Description

Detects when a user downloads a file by using CertOC.exe

```yml
title: File Download via CertOC.EXE
id: 70ad0861-d1fe-491c-a45f-fa48148a300d
related:
    - id: b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a
      type: similar
status: test
description: Detects when a user downloads a file by using CertOC.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certoc/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/05/16
modified: 2023/10/18
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certoc.exe'
        - OriginalFileName: 'CertOC.exe'
    selection_cli:
        CommandLine|contains|all:
            - '-GetCACAPS'
            - 'http'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
