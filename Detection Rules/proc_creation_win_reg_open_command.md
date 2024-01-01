---
title: "Suspicious Reg Add Open Command"
status: "test"
created: "2021/12/20"
last_modified: "2022/12/25"
tags: [credential_access, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Reg Add Open Command

### Description

Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key

```yml
title: Suspicious Reg Add Open Command
id: dd3ee8cc-f751-41c9-ba53-5a32ed47e563
status: test
description: Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
author: frack113
date: 2021/12/20
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
            - 'hkcu\software\classes\ms-settings\shell\open\command'
            - '/ve '
            - '/d'
    selection_2:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
            - 'hkcu\software\classes\ms-settings\shell\open\command'
            - '/v'
            - 'DelegateExecute'
    selection_3:
        CommandLine|contains|all:
            - 'reg'
            - 'delete'
            - 'hkcu\software\classes\ms-settings'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```
