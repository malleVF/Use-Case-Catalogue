---
title: "Potential Credential Dumping Via LSASS Process Clone"
status: "test"
created: "2021/11/27"
last_modified: "2023/03/02"
tags: [credential_access, t1003, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Potential Credential Dumping Via LSASS Process Clone

### Description

Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity

```yml
title: Potential Credential Dumping Via LSASS Process Clone
id: c8da0dfd-4ed0-4b68-962d-13c9c884384e
status: test
description: Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity
references:
    - https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
    - https://twitter.com/Hexacorn/status/1420053502554951689
    - https://twitter.com/SBousseaden/status/1464566846594691073?s=20
author: Florian Roth (Nextron Systems), Samir Bousseaden
date: 2021/11/27
modified: 2023/03/02
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Windows\System32\lsass.exe'
        Image|endswith: '\Windows\System32\lsass.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
