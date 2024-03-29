---
title: "New Firewall Rule Added In Windows Firewall Exception List"
status: "experimental"
created: "2022/02/19"
last_modified: "2023/09/09"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: "firewall-as"
level: "medium"
---

## New Firewall Rule Added In Windows Firewall Exception List

### Description

Detects when a rule has been added to the Windows Firewall exception list

```yml
title: New Firewall Rule Added In Windows Firewall Exception List
id: cde0a575-7d3d-4a49-9817-b8004a7bf105
status: experimental
description: Detects when a rule has been added to the Windows Firewall exception list
references:
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
author: frack113
date: 2022/02/19
modified: 2023/09/09
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    product: windows
    service: firewall-as
detection:
    selection:
        EventID:
            - 2004 # A rule has been added to the Windows Defender Firewall exception list
            - 2071 # A rule has been added to the Windows Defender Firewall exception list. (Windows 11)
    filter_main_block:
        Action: 2
    filter_main_installations:
        - ApplicationPath|startswith:
              - 'C:\Program Files\'
              - 'C:\Program Files (x86)\'
        - ModifyingApplication|startswith: 'C:\Windows\WinSxS\'  # TiWorker.exe
        - ModifyingApplication:
              - 'C:\Windows\System32\oobe\Setup.exe'
              - 'C:\Windows\SysWOW64\msiexec.exe'
              - 'C:\Windows\System32\svchost.exe'
              - 'C:\Windows\System32\dllhost.exe'
              - 'C:\Program Files\Windows Defender\MsMpEng.exe'
    filter_optional_msmpeng:
        ModifyingApplication|startswith: 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
        ModifyingApplication|endswith: '\MsMpEng.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
level: medium

```
