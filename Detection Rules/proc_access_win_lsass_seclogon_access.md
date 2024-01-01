---
title: "Suspicious LSASS Access Via MalSecLogon"
status: "test"
created: "2022/06/29"
last_modified: ""
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious LSASS Access Via MalSecLogon

### Description

Detects suspicious access to LSASS handle via a call trace to "seclogon.dll" with a suspicious access right.

```yml
title: Suspicious LSASS Access Via MalSecLogon
id: 472159c5-31b9-4f56-b794-b766faa8b0a7
status: test
description: Detects suspicious access to LSASS handle via a call trace to "seclogon.dll" with a suspicious access right.
references:
    - https://twitter.com/SBousseaden/status/1541920424635912196
    - https://github.com/elastic/detection-rules/blob/2bc1795f3d7bcc3946452eb4f07ae799a756d94e/rules/windows/credential_access_lsass_handle_via_malseclogon.toml
    - https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
author: Samir Bousseaden (original elastic rule), Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/29
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: '\svchost.exe'
        GrantedAccess: '0x14c0'
        CallTrace|contains: 'seclogon.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```