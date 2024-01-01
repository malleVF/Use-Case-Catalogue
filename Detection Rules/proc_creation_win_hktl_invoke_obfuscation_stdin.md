---
title: "Invoke-Obfuscation STDIN+ Launcher"
status: "test"
created: "2020/10/15"
last_modified: "2022/11/17"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation STDIN+ Launcher

### Description

Detects Obfuscated use of stdin to execute PowerShell

```yml
title: Invoke-Obfuscation STDIN+ Launcher
id: 6c96fc76-0eb1-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of stdin to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 25)
author: Jonathan Cheong, oscd.community
date: 2020/10/15
modified: 2022/11/17
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        # CommandLine|re: '.*cmd.{0,5}(?:\/c|\/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
        # Example 1: c:\windows\sYstEm32\CmD.eXE /C"echO\Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -NoEXiT -"
        # Example 2: c:\WiNDOws\sysTEm32\cmd.EXe /C " ECHo Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -nol ${EXEcUtIONCONTeXT}.INvOkEComMANd.InvOKEScRIPt( $InpUt )"
        CommandLine|contains|all:
            - 'cmd'
            - 'powershell'
        CommandLine|contains:
            - '/c'
            - '/r'
    selection_other:
        - CommandLine|contains: 'noexit'
        - CommandLine|contains|all:
              - 'input'
              - '$'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```