---
title: "New Generic Credentials Added Via Cmdkey.EXE"
status: "test"
created: "2023/02/03"
last_modified: ""
tags: [credential_access, t1003_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New Generic Credentials Added Via Cmdkey.EXE

### Description

Detects usage of cmdkey to add generic credentials. As an example, this has to be used before connecting to an RDP session via command line interface.

```yml
title: New Generic Credentials Added Via Cmdkey.EXE
id: b1ec66c6-f4d1-4b5c-96dd-af28ccae7727
status: test
description: Detects usage of cmdkey to add generic credentials. As an example, this has to be used before connecting to an RDP session via command line interface.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.001/T1021.001.md#t1021001---remote-desktop-protocol
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/03
tags:
    - attack.credential_access
    - attack.t1003.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmdkey.exe'
        - OriginalFileName: 'cmdkey.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' /g'
            - ' /u'
            - ' /p'
    condition: all of selection*
falsepositives:
    - Legitimate usage for administration purposes
level: medium

```
