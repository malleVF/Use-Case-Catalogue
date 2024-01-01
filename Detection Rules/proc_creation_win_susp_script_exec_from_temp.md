---
title: "Suspicious Script Execution From Temp Folder"
status: "test"
created: "2021/07/14"
last_modified: "2022/10/05"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Script Execution From Temp Folder

### Description

Detects a suspicious script executions from temporary folder

```yml
title: Suspicious Script Execution From Temp Folder
id: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
status: test
description: Detects a suspicious script executions from temporary folder
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
author: Florian Roth (Nextron Systems), Max Altgelt (Nextron Systems), Tim Shelton
date: 2021/07/14
modified: 2022/10/05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains:
            - '\Windows\Temp'
            - '\Temporary Internet'
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\Temp'
            - '%TEMP%'
            - '%TMP%'
            - '%LocalAppData%\Temp'
    filter:
        CommandLine|contains:
            - ' >'
            - 'Out-File'
            - 'ConvertTo-Json'
            - '-WindowStyle hidden -Verb runAs'  # VSCode behaviour if file cannot be written as current user
            - '\Windows\system32\config\systemprofile\AppData\Local\Temp\Amazon\EC2-Windows\' # EC2 AWS
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: high

```