---
title: "Cisco Crypto Commands"
status: "test"
created: "2019/08/12"
last_modified: "2023/01/04"
tags: [credential_access, defense_evasion, t1553_004, t1552_004, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "high"
---

## Cisco Crypto Commands

### Description

Show when private keys are being exported from the device, or when new certificates are installed

```yml
title: Cisco Crypto Commands
id: 1f978c6a-4415-47fb-aca5-736a44d7ca3d
status: test
description: Show when private keys are being exported from the device, or when new certificates are installed
author: Austin Clark
date: 2019/08/12
modified: 2023/01/04
tags:
    - attack.credential_access
    - attack.defense_evasion
    - attack.t1553.004
    - attack.t1552.004
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'crypto pki export'
        - 'crypto pki import'
        - 'crypto pki trustpoint'
    condition: keywords
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
falsepositives:
    - Not commonly run by administrators. Also whitelist your known good certificates
level: high

```
