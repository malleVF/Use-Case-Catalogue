---
title: "Powerup Write Hijack DLL"
status: "test"
created: "2021/08/21"
last_modified: "2022/10/09"
tags: [persistence, privilege_escalation, defense_evasion, t1574_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Powerup Write Hijack DLL

### Description

Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation.
In it's default mode, it builds a self deleting .bat file which executes malicious command.
The detection rule relies on creation of the malicious bat file (debug.bat by default).


```yml
title: Powerup Write Hijack DLL
id: 602a1f13-c640-4d73-b053-be9a2fa58b96
status: test
description: |
    Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation.
    In it's default mode, it builds a self deleting .bat file which executes malicious command.
    The detection rule relies on creation of the malicious bat file (debug.bat by default).
references:
    - https://powersploit.readthedocs.io/en/latest/Privesc/Write-HijackDll/
author: Subhash Popuri (@pbssubhash)
date: 2021/08/21
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1574.001
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetFilename|endswith: '.bat'
    condition: selection
falsepositives:
    - Any powershell script that creates bat files # highly unlikely (untested)
level: high

```
