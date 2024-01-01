---
title: "Password Protected ZIP File Opened (Suspicious Filenames)"
status: "test"
created: "2022/05/09"
last_modified: ""
tags: [command_and_control, defense_evasion, t1027, t1105, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Password Protected ZIP File Opened (Suspicious Filenames)

### Description

Detects the extraction of password protected ZIP archives with suspicious file names. See the filename variable for more details on which file has been opened.

```yml
title: Password Protected ZIP File Opened (Suspicious Filenames)
id: 54f0434b-726f-48a1-b2aa-067df14516e4
status: test
description: Detects the extraction of password protected ZIP archives with suspicious file names. See the filename variable for more details on which file has been opened.
references:
    - https://twitter.com/sbousseaden/status/1523383197513379841
author: Florian Roth (Nextron Systems)
date: 2022/05/09
tags:
    - attack.command_and_control
    - attack.defense_evasion
    - attack.t1027
    - attack.t1105
    - attack.t1036
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5379
        TargetName|contains: 'Microsoft_Windows_Shell_ZipFolder:filename'
    selection_filename:
        TargetName|contains:
            - 'invoice'
            - 'new order'
            - 'rechnung'
            - 'factura'
            - 'delivery'
            - 'purchase'
            - 'order'
            - 'payment'
    condition: selection and selection_filename
falsepositives:
    - Legitimate used of encrypted ZIP files
level: high

```
