---
title: "HackTool - SysmonEnte Execution"
status: "test"
created: "2022/09/07"
last_modified: "2023/11/28"
tags: [defense_evasion, t1562_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - SysmonEnte Execution

### Description

Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon

```yml
title: HackTool - SysmonEnte Execution
id: d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
status: test
description: Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon
references:
    - https://codewhitesec.blogspot.com/2022/09/attacks-on-sysmon-revisited-sysmonente.html
    - https://github.com/codewhitesec/SysmonEnte/
    - https://github.com/codewhitesec/SysmonEnte/blob/main/screens/1.png
author: Florian Roth (Nextron Systems)
date: 2022/09/07
modified: 2023/11/28
tags:
    - attack.defense_evasion
    - attack.t1562.002
logsource:
    category: process_access
    product: windows
detection:
    selection_sysmon:
        TargetImage|contains:
            - ':\Windows\Sysmon.exe'
            - ':\Windows\Sysmon64.exe'
        GrantedAccess: '0x1400'
    selection_calltrace:
        CallTrace: 'Ente'
    filter_main_generic:
        SourceImage|contains:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
    filter_main_msdefender:
        SourceImage|contains: ':\ProgramData\Microsoft\Windows Defender\Platform\'
        SourceImage|endswith: '\MsMpEng.exe'
    condition: ( selection_sysmon and not 1 of filter_main_* ) or selection_calltrace
falsepositives:
    - Unknown
level: high

```