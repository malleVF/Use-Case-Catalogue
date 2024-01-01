---
title: "Potential PowerShell Execution Via DLL"
status: "test"
created: "2018/08/25"
last_modified: "2023/01/26"
tags: [defense_evasion, t1218_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential PowerShell Execution Via DLL

### Description

Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll

```yml
title: Potential PowerShell Execution Via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: test
description: Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll
references:
    - https://github.com/p3nt4/PowerShdll/blob/62cfa172fb4e1f7f4ac00ca942685baeb88ff356/README.md
author: Markus Neis, Nasreddine Bencherchali
date: 2018/08/25
modified: 2023/01/26
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\rundll32.exe'
              - '\regsvcs.exe'
              - '\InstallUtil.exe'
              - '\regasm.exe'
        - OriginalFileName:
              - 'RUNDLL32.EXE'
              - 'RegSvcs.exe'
              - 'InstallUtil.exe'
              - 'RegAsm.exe'
    selection_cli:
        CommandLine|contains:
            - 'Default.GetString'
            - 'FromBase64String'
            - 'Invoke-Expression'
            - 'IEX '
            - 'Invoke-Command'
            - 'ICM '
            - 'DownloadString'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
