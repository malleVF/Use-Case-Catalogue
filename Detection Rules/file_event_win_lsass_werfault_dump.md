---
title: "WerFault LSASS Process Memory Dump"
status: "test"
created: "2022/06/27"
last_modified: ""
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## WerFault LSASS Process Memory Dump

### Description

Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials

```yml
title: WerFault LSASS Process Memory Dump
id: c3e76af5-4ce0-4a14-9c9a-25ceb8fda182
status: test
description: Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials
references:
    - https://github.com/helpsystems/nanodump
author: Florian Roth (Nextron Systems)
date: 2022/06/27
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: C:\WINDOWS\system32\WerFault.exe
        TargetFilename|contains:
            - '\lsass'
            - 'lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
