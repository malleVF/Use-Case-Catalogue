---
title: "HackTool - SharpUp PrivEsc Tool Execution"
status: "experimental"
created: "2022/08/20"
last_modified: "2023/02/13"
tags: [privilege_escalation, t1615, t1569_002, t1574_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## HackTool - SharpUp PrivEsc Tool Execution

### Description

Detects the use of SharpUp, a tool for local privilege escalation

```yml
title: HackTool - SharpUp PrivEsc Tool Execution
id: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
status: experimental
description: Detects the use of SharpUp, a tool for local privilege escalation
references:
    - https://github.com/GhostPack/SharpUp
author: Florian Roth (Nextron Systems)
date: 2022/08/20
modified: 2023/02/13
tags:
    - attack.privilege_escalation
    - attack.t1615
    - attack.t1569.002
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpUp.exe'
        - Description: 'SharpUp'
        - CommandLine|contains:
              - 'HijackablePaths'
              - 'UnquotedServicePath'
              - 'ProcessDLLHijack'
              - 'ModifiableServiceBinaries'
              - 'ModifiableScheduledTask'
              - 'DomainGPPPassword'
              - 'CachedGPPPassword'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
