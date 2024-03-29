---
title: "PUA - CsExec Execution"
status: "experimental"
created: "2022/08/22"
last_modified: "2023/02/21"
tags: [resource_development, t1587_001, execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - CsExec Execution

### Description

Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative

```yml
title: PUA - CsExec Execution
id: d08a2711-ee8b-4323-bdec-b7d85e892b31
status: experimental
description: Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative
references:
    - https://github.com/malcomvetter/CSExec
    - https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/
author: Florian Roth (Nextron Systems)
date: 2022/08/22
modified: 2023/02/21
tags:
    - attack.resource_development
    - attack.t1587.001
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csexec.exe'
    selection_pe:
        Description: 'csexec'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```
