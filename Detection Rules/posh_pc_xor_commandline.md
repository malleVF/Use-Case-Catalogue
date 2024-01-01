---
title: "Suspicious XOR Encoded PowerShell Command Line - PowerShell"
status: "test"
created: "2020/06/29"
last_modified: "2023/10/27"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious XOR Encoded PowerShell Command Line - PowerShell

### Description

Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.

```yml
title: Suspicious XOR Encoded PowerShell Command Line - PowerShell
id: 812837bb-b17f-45e9-8bd0-0ec35d2e3bd6
status: test
description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=46
author: Teymur Kheirkhabarov, Harish Segar (rule)
date: 2020/06/29
modified: 2023/10/27
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains: 'HostName=ConsoleHost'
    filter:
        Data|contains:
            - 'bxor'
            - 'char'
            - 'join'
    condition: selection and filter
falsepositives:
    - Unknown
level: medium

```