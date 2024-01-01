---
title: "Potential In-Memory Execution Using Reflection.Assembly"
status: "test"
created: "2022/12/25"
last_modified: ""
tags: [defense_evasion, t1620, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential In-Memory Execution Using Reflection.Assembly

### Description

Detects usage of "Reflection.Assembly" load functions to dynamically load assemblies in memory

```yml
title: Potential In-Memory Execution Using Reflection.Assembly
id: ddcd88cb-7f62-4ce5-86f9-1704190feb0a
status: test
description: Detects usage of "Reflection.Assembly" load functions to dynamically load assemblies in memory
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
author: frack113
date: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.t1620
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
    selection:
        ScriptBlockText|contains: '[Reflection.Assembly]::load'
    condition: selection
falsepositives:
    - Legitimate use of the library
level: medium

```
