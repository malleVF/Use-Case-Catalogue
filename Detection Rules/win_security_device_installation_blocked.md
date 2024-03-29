---
title: "Device Installation Blocked"
status: "test"
created: "2022/10/14"
last_modified: ""
tags: [initial_access, t1200, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Device Installation Blocked

### Description

Detects an installation of a device that is forbidden by the system policy

```yml
title: Device Installation Blocked
id: c9eb55c3-b468-40ab-9089-db2862e42137
status: test
description: Detects an installation of a device that is forbidden by the system policy
references:
    - https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6423
author: frack113
date: 2022/10/14
tags:
    - attack.initial_access
    - attack.t1200
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID: 6423
    condition: selection
falsepositives:
    - Unknown
level: medium

```
