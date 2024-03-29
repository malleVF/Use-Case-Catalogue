---
title: "HackTool - SharpImpersonation Execution"
status: "experimental"
created: "2022/12/27"
last_modified: "2023/02/13"
tags: [privilege_escalation, defense_evasion, t1134_001, t1134_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - SharpImpersonation Execution

### Description

Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively

```yml
title: HackTool - SharpImpersonation Execution
id: f89b08d0-77ad-4728-817b-9b16c5a69c7a
related:
    - id: cf0c254b-22f1-4b2b-8221-e137b3c0af94
      type: similar
status: experimental
description: Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
references:
    - https://s3cur3th1ssh1t.github.io/SharpImpersonation-Introduction/
    - https://github.com/S3cur3Th1sSh1t/SharpImpersonation
author: Sai Prashanth Pulisetti @pulisettis, Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/27
modified: 2023/02/13
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1134.001
    - attack.t1134.003
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\SharpImpersonation.exe'
        - OriginalFileName: 'SharpImpersonation.exe'
    selection_cli:
        - CommandLine|contains|all:
              - ' user:'
              - ' binary:'
        - CommandLine|contains|all:
              - ' user:'
              - ' shellcode:'
        - CommandLine|contains:
              - ' technique:CreateProcessAsUserW'
              - ' technique:ImpersonateLoggedOnuser'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```
