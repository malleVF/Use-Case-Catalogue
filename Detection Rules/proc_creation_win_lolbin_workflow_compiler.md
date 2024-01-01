---
title: "Microsoft Workflow Compiler Execution"
status: "test"
created: "2019/01/16"
last_modified: "2023/02/03"
tags: [defense_evasion, execution, t1127, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Microsoft Workflow Compiler Execution

### Description

Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.

```yml
title: Microsoft Workflow Compiler Execution
id: 419dbf2b-8a9b-4bea-bf99-7544b050ec8d
status: test
description: Detects invocation of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code.
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/
author: Nik Seetharaman, frack113
date: 2019/01/16
modified: 2023/02/03
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1127
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Microsoft.Workflow.Compiler.exe'
        - OriginalFileName: 'Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: medium

```
