---
title: "PsExec Service Installation"
status: "experimental"
created: "2017/06/12"
last_modified: "2023/08/04"
tags: [execution, t1569_002, s0029, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## PsExec Service Installation

### Description

Detects PsExec service installation and execution events

```yml
title: PsExec Service Installation
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: experimental
description: Detects PsExec service installation and execution events
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
author: Thomas Patzke
date: 2017/06/12
modified: 2023/08/04
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ServiceName: 'PSEXESVC'
        - ImagePath|endswith: '\PSEXESVC.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
