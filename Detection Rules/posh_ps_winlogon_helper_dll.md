---
title: "Winlogon Helper DLL"
status: "test"
created: "2019/10/21"
last_modified: "2022/07/07"
tags: [persistence, t1547_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Winlogon Helper DLL

### Description

Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are
used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to
load and execute malicious DLLs and/or executables.


```yml
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: test
description: |
    Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
    Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are
    used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to
    load and execute malicious DLLs and/or executables.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.004/T1547.004.md
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2022/07/07
tags:
    - attack.persistence
    - attack.t1547.004
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'CurrentVersion\Winlogon'
    selection2:
        ScriptBlockText|contains:
            - 'Set-ItemProperty'
            - 'New-Item'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```