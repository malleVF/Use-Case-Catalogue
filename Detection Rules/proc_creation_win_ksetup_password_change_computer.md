---
title: "Computer Password Change Via Ksetup.EXE"
status: "experimental"
created: "2023/04/06"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Computer Password Change Via Ksetup.EXE

### Description

Detects password change for the computer's domain account or host principal via "ksetup.exe"

```yml
title: Computer Password Change Via Ksetup.EXE
id: de16d92c-c446-4d53-8938-10aeef41c8b6
status: experimental
description: Detects password change for the computer's domain account or host principal via "ksetup.exe"
references:
    - https://twitter.com/Oddvarmoe/status/1641712700605513729
    - https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/04/06
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ksetup.exe'
        - OriginalFileName: 'ksetup.exe'
    selection_cli:
        CommandLine|contains: ' /setcomputerpassword '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
