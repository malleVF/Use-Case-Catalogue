---
title: "Suspicious PowerShell Encoded Command Patterns"
status: "test"
created: "2022/05/24"
last_modified: "2023/01/05"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious PowerShell Encoded Command Patterns

### Description

Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains

```yml
title: Suspicious PowerShell Encoded Command Patterns
id: b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c
status: test
description: Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains
references:
    - https://app.any.run/tasks/b9040c63-c140-479b-ad59-f1bb56ce7a97/
author: Florian Roth (Nextron Systems)
date: 2022/05/24
modified: 2023/01/05
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
              - 'PowerShell.Exe'
              - 'pwsh.dll'
    selection_flags:
        CommandLine|contains:
            - ' -e '
            - ' -en '
            - ' -enc '
            - ' -enco'
    selection_encoded:
        CommandLine|contains:
            - ' JAB'
            - ' SUVYI'
            - ' SQBFAFgA'
            - ' aWV4I'
            - ' IAB'
            - ' PAA'
            - ' aQBlAHgA'
    filter_gcworker:
        ParentImage|contains:
            - 'C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\'
            - '\gc_worker.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Other tools that work with encoded scripts in the command line instead of script files
level: high

```