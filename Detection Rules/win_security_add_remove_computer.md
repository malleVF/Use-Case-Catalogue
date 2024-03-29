---
title: "Add or Remove Computer from DC"
status: "test"
created: "2022/10/14"
last_modified: ""
tags: [defense_evasion, t1207, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Add or Remove Computer from DC

### Description

Detects the creation or removal of a computer. Can be used to detect attacks such as DCShadow via the creation of a new SPN.

```yml
title: Add or Remove Computer from DC
id: 20d96d95-5a20-4cf1-a483-f3bda8a7c037
status: test
description: Detects the creation or removal of a computer. Can be used to detect attacks such as DCShadow via the creation of a new SPN.
references:
    - https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4741
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4743
author: frack113
date: 2022/10/14
tags:
    - attack.defense_evasion
    - attack.t1207
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID:
            - 4741
            - 4743
    condition: selection
falsepositives:
    - Unknown
level: low

```
