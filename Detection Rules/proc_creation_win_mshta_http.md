---
title: "Remotely Hosted HTA File Executed Via Mshta.EXE"
status: "experimental"
created: "2022/08/08"
last_modified: "2023/02/06"
tags: [defense_evasion, execution, t1218_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remotely Hosted HTA File Executed Via Mshta.EXE

### Description

Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file

```yml
title: Remotely Hosted HTA File Executed Via Mshta.EXE
id: b98d0db6-511d-45de-ad02-e82a98729620
status: experimental
description: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
references:
    - https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/08
modified: 2023/02/06
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
