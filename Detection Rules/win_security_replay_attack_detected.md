---
title: "Replay Attack Detected"
status: "test"
created: "2022/10/14"
last_modified: ""
tags: [credential_access, t1558, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Replay Attack Detected

### Description

Detects possible Kerberos Replay Attack on the domain controllers when "KRB_AP_ERR_REPEAT" Kerberos response is sent to the client

```yml
title: Replay Attack Detected
id: 5a44727c-3b85-4713-8c44-4401d5499629
status: test
description: Detects possible Kerberos Replay Attack on the domain controllers when "KRB_AP_ERR_REPEAT" Kerberos response is sent to the client
references:
    - https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4649
author: frack113
date: 2022/10/14
tags:
    - attack.credential_access
    - attack.t1558
logsource:
    service: security
    product: windows
detection:
    selection:
        EventID: 4649
    condition: selection
falsepositives:
    - Unknown
level: high

```
