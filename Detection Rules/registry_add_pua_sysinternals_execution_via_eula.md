---
title: "PUA - Sysinternal Tool Execution - Registry"
status: "experimental"
created: "2017/08/28"
last_modified: "2023/02/07"
tags: [resource_development, t1588_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## PUA - Sysinternal Tool Execution - Registry

### Description

Detects the execution of a Sysinternals Tool via the creation of the "accepteula" registry key

```yml
title: PUA - Sysinternal Tool Execution - Registry
id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
status: experimental
description: Detects the execution of a Sysinternals Tool via the creation of the "accepteula" registry key
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
author: Markus Neis
date: 2017/08/28
modified: 2023/02/07
tags:
    - attack.resource_development
    - attack.t1588.002
logsource:
    product: windows
    category: registry_add
detection:
    selection:
        EventType: CreateKey
        TargetObject|endswith: '\EulaAccepted'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low

```
