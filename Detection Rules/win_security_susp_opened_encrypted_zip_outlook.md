---
title: "Password Protected ZIP File Opened (Email Attachment)"
status: "test"
created: "2022/05/09"
last_modified: ""
tags: [defense_evasion, initial_access, t1027, t1566_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Password Protected ZIP File Opened (Email Attachment)

### Description

Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.

```yml
title: Password Protected ZIP File Opened (Email Attachment)
id: 571498c8-908e-40b4-910b-d2369159a3da
status: test
description: Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.
references:
    - https://twitter.com/sbousseaden/status/1523383197513379841
author: Florian Roth (Nextron Systems)
date: 2022/05/09
tags:
    - attack.defense_evasion
    - attack.initial_access
    - attack.t1027
    - attack.t1566.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5379
        TargetName|contains|all:
            - 'Microsoft_Windows_Shell_ZipFolder:filename'
            - '\Temporary Internet Files\Content.Outlook'
    condition: selection
falsepositives:
    - Legitimate used of encrypted ZIP files
level: high

```
