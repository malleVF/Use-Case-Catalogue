---
title: "Potential Suspicious Registry File Imported Via Reg.EXE"
status: "experimental"
created: "2022/08/01"
last_modified: "2023/02/05"
tags: [t1112, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Suspicious Registry File Imported Via Reg.EXE

### Description

Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility

```yml
title: Potential Suspicious Registry File Imported Via Reg.EXE
id: 62e0298b-e994-4189-bc87-bc699aa62d97
related:
    - id: 73bba97f-a82d-42ce-b315-9182e76c57b1
      type: derived
status: experimental
description: Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-import
author: frack113, Nasreddine Bencherchali
date: 2022/08/01
modified: 2023/02/05
tags:
    - attack.t1112
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_cli:
        CommandLine|contains: ' import '
    selection_paths:
        CommandLine|contains:
            - 'C:\Users\'
            - '%temp%'
            - '%tmp%'
            - '%appdata%'
            - '\AppData\Local\Temp\'
            - 'C:\Windows\Temp\'
            - 'C:\ProgramData\'
    condition: all of selection_*
falsepositives:
    - Legitimate import of keys
level: medium

```
