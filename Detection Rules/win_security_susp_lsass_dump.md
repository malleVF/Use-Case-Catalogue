---
title: "Password Dumper Activity on LSASS"
status: "test"
created: "2017/02/12"
last_modified: "2022/10/09"
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Password Dumper Activity on LSASS

### Description

Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN

```yml
title: Password Dumper Activity on LSASS
id: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
status: test
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
references:
    - https://twitter.com/jackcr/status/807385668833968128
author: sigma
date: 2017/02/12
modified: 2022/10/09
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ProcessName|endswith: '\lsass.exe'
        AccessMask: '0x705'
        ObjectType: 'SAM_DOMAIN'
    condition: selection
falsepositives:
    - Unknown
level: high

```
