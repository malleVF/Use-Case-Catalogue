---
title: "Invoke-Obfuscation VAR+ Launcher - Security"
status: "test"
created: "2020/10/15"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation VAR+ Launcher - Security

### Description

Detects Obfuscated use of Environment Variables to execute PowerShell

```yml
title: Invoke-Obfuscation VAR+ Launcher - Security
id: dcf2db1f-f091-425b-a821-c05875b8925a
related:
    - id: 8ca7004b-e620-4ecb-870e-86129b5b8e75
      type: derived
status: test
description: Detects Obfuscated use of Environment Variables to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 24)
author: Jonathan Cheong, oscd.community
date: 2020/10/15
modified: 2022/11/29
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        # ServiceFileName|re: '.*cmd.{0,5}(?:\/c|\/r)(?:\s|)\"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\\"\s+?\-f(?:.*\)){1,}.*\"'
        # Example 1: C:\winDoWs\SySTeM32\cmd.Exe /C"SET NOtI=Invoke-Expression (New-Object Net.WebClient).DownloadString&& PowERshElL -NOl SET-iteM ( 'VAR' + 'i'+ 'A' + 'blE:Ao6' + 'I0') ( [TYpe](\"{2}{3}{0}{1}\"-F 'iRoN','mENT','e','nv') ) ; ${exECUtIONCOnTEXT}.\"IN`VO`KecOmMaND\".\"inVo`KES`crIPt\"( ( ( GEt-VAriAble ( 'a' + 'o6I0') -vaLU )::(\"{1}{4}{2}{3}{0}\" -f'e','gETenvIR','NtvaRIa','BL','ONme' ).Invoke(( \"{0}{1}\"-f'n','oti' ),( \"{0}{1}\" -f'pRoC','esS') )) )"
        # Example 2: cMD.exe /C "seT SlDb=Invoke-Expression (New-Object Net.WebClient).DownloadString&& pOWErShell .(( ^&(\"{1}{0}{2}{3}\" -f 'eT-vaR','G','iab','lE' ) (\"{0}{1}\" -f '*m','DR*' ) ).\"na`ME\"[3,11,2]-JOIN'' ) ( ( ^&(\"{0}{1}\" -f'g','CI' ) (\"{0}{1}\" -f 'ENV',':SlDb' ) ).\"VA`luE\" ) "
        ServiceFileName|contains|all:
            - 'cmd'
            - '"set'
            - '-f'
        ServiceFileName|contains:
            - '/c'
            - '/r'
    condition: selection
falsepositives:
    - Unknown
level: high

```