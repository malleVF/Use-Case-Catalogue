---
title: "KrbRelayUp Attack Pattern"
status: "test"
created: "2022/04/27"
last_modified: ""
tags: [privilege_escalation, credential_access, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## KrbRelayUp Attack Pattern

### Description

Detects logon events that have characteristics of events generated during an attack with KrbRelayUp and the like

```yml
title: KrbRelayUp Attack Pattern
id: 749c9f5e-b353-4b90-a9c1-05243357ca4b
status: test
description: Detects logon events that have characteristics of events generated during an attack with KrbRelayUp and the like
references:
    - https://twitter.com/sbousseaden/status/1518976397364056071?s=12&t=qKO5eKHvWhAP19a50FTZ7g
    - https://github.com/elastic/detection-rules/blob/fb6ee2c69864ffdfe347bf3b050cb931f53067a6/rules/windows/privilege_escalation_krbrelayup_suspicious_logon.toml
author: '@SBousseaden, Florian Roth'
date: 2022/04/27
tags:
    - attack.privilege_escalation
    - attack.credential_access
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'Kerberos'
        IpAddress: '127.0.0.1'
        TargetUserSid|startswith: 'S-1-5-21-'
        TargetUserSid|endswith: '-500'
    condition: selection
falsepositives:
    - Unknown
level: high

```
