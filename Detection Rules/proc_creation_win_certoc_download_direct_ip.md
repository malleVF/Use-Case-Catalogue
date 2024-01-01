---
title: "File Download From IP Based URL Via CertOC.EXE"
status: "experimental"
created: "2023/10/18"
last_modified: ""
tags: [command_and_control, execution, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## File Download From IP Based URL Via CertOC.EXE

### Description

Detects when a user downloads a file from an IP based URL using CertOC.exe

```yml
title: File Download From IP Based URL Via CertOC.EXE
id: b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a
related:
    - id: 70ad0861-d1fe-491c-a45f-fa48148a300d
      type: similar
status: experimental
description: Detects when a user downloads a file from an IP based URL using CertOC.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certoc/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/10/18
tags:
    - attack.command_and_control
    - attack.execution
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certoc.exe'
        - OriginalFileName: 'CertOC.exe'
    selection_ip:
        CommandLine|re: '://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    selection_cli:
        CommandLine|contains: '-GetCACAPS'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
