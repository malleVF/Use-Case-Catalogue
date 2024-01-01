---
title: "Suspicious Execution of InstallUtil Without Log"
status: "test"
created: "2022/01/23"
last_modified: "2022/02/04"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Execution of InstallUtil Without Log

### Description

Uses the .NET InstallUtil.exe application in order to execute image without log

```yml
title: Suspicious Execution of InstallUtil Without Log
id: d042284c-a296-4988-9be5-f424fadcc28c
status: test
description: Uses the .NET InstallUtil.exe application in order to execute image without log
references:
    - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
    - https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool
author: frack113
date: 2022/01/23
modified: 2022/02/04
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\InstallUtil.exe'
        Image|contains: 'Microsoft.NET\Framework'
        CommandLine|contains|all:
            - '/logfile= '
            - '/LogToConsole=false'
    condition: selection
falsepositives:
    - Unknown
level: medium

```