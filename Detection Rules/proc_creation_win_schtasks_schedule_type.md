---
title: "Suspicious Schtasks Schedule Types"
status: "test"
created: "2022/09/09"
last_modified: ""
tags: [execution, t1053_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Schtasks Schedule Types

### Description

Detects scheduled task creations or modification on a suspicious schedule type

```yml
title: Suspicious Schtasks Schedule Types
id: 24c8392b-aa3c-46b7-a545-43f71657fe98
related:
    - id: 7a02e22e-b885-4404-b38b-1ddc7e65258a
      type: similar
status: test
description: Detects scheduled task creations or modification on a suspicious schedule type
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/09
tags:
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_time:
        CommandLine|contains:
            - ' ONLOGON '
            - ' ONSTART '
            - ' ONCE '
            - ' ONIDLE '
    filter_privs:
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
            - 'HIGHEST'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Legitimate processes that run at logon. Filter according to your environment
level: high

```