---
title: "Suspicious Teams Application Related ObjectAcess Event"
status: "test"
created: "2022/09/16"
last_modified: ""
tags: [credential_access, t1528, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Suspicious Teams Application Related ObjectAcess Event

### Description

Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.

```yml
title: Suspicious Teams Application Related ObjectAcess Event
id: 25cde13e-8e20-4c29-b949-4e795b76f16f
status: test
description: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
references:
    - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
    - https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
author: '@SerkinValery'
date: 2022/09/16
tags:
    - attack.credential_access
    - attack.t1528
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        ObjectName|contains:
            - '\Microsoft\Teams\Cookies'
            - '\Microsoft\Teams\Local Storage\leveldb'
    filter:
        ProcessName|contains: '\Microsoft\Teams\current\Teams.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
