---
title: "PSAsyncShell - Asynchronous TCP Reverse Shell"
status: "test"
created: "2022/10/04"
last_modified: ""
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PSAsyncShell - Asynchronous TCP Reverse Shell

### Description

Detects the use of PSAsyncShell an Asynchronous TCP Reverse Shell written in powershell

```yml
title: PSAsyncShell - Asynchronous TCP Reverse Shell
id: afd3df04-948d-46f6-ae44-25966c44b97f
status: test
description: Detects the use of PSAsyncShell an Asynchronous TCP Reverse Shell written in powershell
references:
    - https://github.com/JoelGMSec/PSAsyncShell
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/04
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'PSAsyncShell'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
