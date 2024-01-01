---
title: "Potential Binary Proxy Execution Via VSDiagnostics.EXE"
status: "experimental"
created: "2023/08/03"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Binary Proxy Execution Via VSDiagnostics.EXE

### Description

Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.

```yml
title: Potential Binary Proxy Execution Via VSDiagnostics.EXE
id: ac1c92b4-ac81-405a-9978-4604d78cc47e
status: experimental
description: Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.
references:
    - https://twitter.com/0xBoku/status/1679200664013135872
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/03
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VSDiagnostics.exe'
        - OriginalFileName: 'VSDiagnostics.exe'
    selection_cli_start:
        CommandLine|contains: 'start'
    selection_cli_launch:
        CommandLine|contains:
            - ' /launch:'
            - ' -launch:'
    condition: all of selection_*
falsepositives:
    - Legitimate usage for tracing and diagnostics purposes
level: medium

```