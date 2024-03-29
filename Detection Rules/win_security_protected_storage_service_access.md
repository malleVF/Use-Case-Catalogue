---
title: "Protected Storage Service Access"
status: "test"
created: "2019/08/10"
last_modified: "2021/11/27"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Protected Storage Service Access

### Description

Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers

```yml
title: Protected Storage Service Access
id: 45545954-4016-43c6-855e-eae8f1c369dc
status: test
description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
references:
    - https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/08/10
modified: 2021/11/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName|contains: 'IPC'
        RelativeTargetName: 'protected_storage'
    condition: selection
falsepositives:
    - Unknown
level: high

```
