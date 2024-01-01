---
title: "DPAPI Domain Backup Key Extraction"
status: "test"
created: "2019/06/20"
last_modified: "2022/02/24"
tags: [credential_access, t1003_004, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## DPAPI Domain Backup Key Extraction

### Description

Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers

```yml
title: DPAPI Domain Backup Key Extraction
id: 4ac1f50b-3bd0-4968-902d-868b4647937e
status: test
description: Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers
references:
    - https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/06/20
modified: 2022/02/24
tags:
    - attack.credential_access
    - attack.t1003.004
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectType: 'SecretObject'
        AccessMask: '0x2'
        ObjectName|contains: 'BCKUPKEY'
    condition: selection
falsepositives:
    - Unknown
level: high

```
