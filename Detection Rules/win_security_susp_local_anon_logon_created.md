---
title: "Suspicious Windows ANONYMOUS LOGON Local Account Created"
status: "test"
created: "2019/10/31"
last_modified: "2022/10/09"
tags: [persistence, t1136_001, t1136_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Suspicious Windows ANONYMOUS LOGON Local Account Created

### Description

Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.

```yml
title: Suspicious Windows ANONYMOUS LOGON Local Account Created
id: 1bbf25b9-8038-4154-a50b-118f2a32be27
status: test
description: Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.
references:
    - https://twitter.com/SBousseaden/status/1189469425482829824
author: James Pemberton / @4A616D6573
date: 2019/10/31
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.t1136.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        SamAccountName|contains|all:
            - 'ANONYMOUS'
            - 'LOGON'
    condition: selection
falsepositives:
    - Unknown
level: high

```
