---
title: "NTDS.DIT Created"
status: "experimental"
created: "2023/05/05"
last_modified: ""
tags: [credential_access, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## NTDS.DIT Created

### Description

Detects creation of a file named "ntds.dit" (Active Directory Database)

```yml
title: NTDS.DIT Created
id: 0b8baa3f-575c-46ee-8715-d6f28cc7d33c
status: experimental
description: Detects creation of a file named "ntds.dit" (Active Directory Database)
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/05
tags:
    - attack.credential_access
    - attack.t1003.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'ntds.dit'
    condition: selection
falsepositives:
    - Unknown
level: low

```
