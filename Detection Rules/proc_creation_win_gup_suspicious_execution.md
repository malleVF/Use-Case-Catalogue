---
title: "Suspicious GUP Usage"
status: "test"
created: "2019/02/06"
last_modified: "2022/08/13"
tags: [defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious GUP Usage

### Description

Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks

```yml
title: Suspicious GUP Usage
id: 0a4f6091-223b-41f6-8743-f322ec84930b
status: test
description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
references:
    - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
author: Florian Roth (Nextron Systems)
date: 2019/02/06
modified: 2022/08/13
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GUP.exe'
    filter_programfiles:
        Image|endswith:
            - '\Program Files\Notepad++\updater\GUP.exe'
            - '\Program Files (x86)\Notepad++\updater\GUP.exe'
    filter_user:
        Image|contains: '\Users\'
        Image|endswith:
            - '\AppData\Local\Notepad++\updater\GUP.exe'
            - '\AppData\Roaming\Notepad++\updater\GUP.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
level: high

```
