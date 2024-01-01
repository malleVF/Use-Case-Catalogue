---
title: "Potential Meterpreter/CobaltStrike Activity"
status: "test"
created: "2019/10/26"
last_modified: "2023/02/05"
tags: [privilege_escalation, t1134_001, t1134_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Meterpreter/CobaltStrike Activity

### Description

Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting

```yml
title: Potential Meterpreter/CobaltStrike Activity
id: 15619216-e993-4721-b590-4c520615a67d
status: test
description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
author: Teymur Kheirkhabarov, Ecco, Florian Roth
date: 2019/10/26
modified: 2023/02/05
tags:
    - attack.privilege_escalation
    - attack.t1134.001
    - attack.t1134.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        ParentImage|endswith: '\services.exe'
    selection_technique_1:
        # Examples:
        #   Meterpreter  getsystem technique 1: cmd.exe /c echo 559891bb017 > \\.\pipe\5e120a
        #   CobaltStrike getsystem technique 1b (expanded env var): %COMSPEC% /c echo 559891bb017 > \\.\pipe\5e120a
        #   CobaltStrike getsystem technique 1: %COMSPEC% /c echo 559891bb017 > \\.\pipe\5e120a
        CommandLine|contains|all:
            - '/c'
            - 'echo'
            - '\pipe\'
        CommandLine|contains:
            - 'cmd'
            - '%COMSPEC%'
    selection_technique_2:
        # meterpreter getsystem technique 2: rundll32.exe C:\Users\test\AppData\Local\Temp\tmexsn.dll,a /p:tmexsn
        CommandLine|contains|all:
            - 'rundll32'
            - '.dll,a'
            - '/p:'
    filter_defender:
        CommandLine|contains: 'MpCmdRun'
    condition: selection_img and 1 of selection_technique_* and not 1 of filter_*
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Commandlines containing components like cmd accidentally
    - Jobs and services started with cmd
level: high

```