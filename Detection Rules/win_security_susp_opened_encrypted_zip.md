---
title: "Password Protected ZIP File Opened"
status: "test"
created: "2022/05/09"
last_modified: ""
tags: [defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Password Protected ZIP File Opened

### Description

Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.

```yml
title: Password Protected ZIP File Opened
id: 00ba9da1-b510-4f6b-b258-8d338836180f
status: test
description: Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.
references:
    - https://twitter.com/sbousseaden/status/1523383197513379841
author: Florian Roth (Nextron Systems)
date: 2022/05/09
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5379
        TargetName|contains: 'Microsoft_Windows_Shell_ZipFolder:filename'
    filter:  # avoid overlaps with 54f0434b-726f-48a1-b2aa-067df14516e4
        TargetName|contains: '\Temporary Internet Files\Content.Outlook'
    condition: selection and not filter
falsepositives:
    - Legitimate used of encrypted ZIP files
level: medium

```