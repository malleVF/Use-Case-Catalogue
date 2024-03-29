---
title: "User Logoff Event"
status: "test"
created: "2022/10/14"
last_modified: ""
tags: [, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "informational"
---

## User Logoff Event

### Description

Detects a user log-off activity. Could be used for example to correlate information during forensic investigations

```yml
title: User Logoff Event
id: 0badd08f-c6a3-4630-90d3-6875cca440be
status: test
description: Detects a user log-off activity. Could be used for example to correlate information during forensic investigations
references:
    - https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4647
author: frack113
date: 2022/10/14
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID:
            - 4634
            - 4647
    condition: selection
falsepositives:
    - Unknown
level: informational

```
