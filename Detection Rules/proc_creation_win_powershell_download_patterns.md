---
title: "PowerShell Download Pattern"
status: "test"
created: "2019/01/16"
last_modified: "2023/01/26"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell Download Pattern

### Description

Detects a Powershell process that contains download commands in its command line string

```yml
title: PowerShell Download Pattern
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
related:
    - id: e6c54d94-498c-4562-a37c-b469d8e9a275
      type: derived
status: test
description: Detects a Powershell process that contains download commands in its command line string
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: 2019/01/16
modified: 2023/01/26
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_cli:
        CommandLine|contains|all:
            - 'new-object'
            - 'net.webclient).'
            - 'download'
        CommandLine|contains:
            - 'string('
            - 'file('
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```
