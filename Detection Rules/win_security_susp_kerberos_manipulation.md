---
title: "Kerberos Manipulation"
status: "test"
created: "2017/02/10"
last_modified: "2021/11/27"
tags: [credential_access, t1212, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Kerberos Manipulation

### Description

This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages

```yml
title: Kerberos Manipulation
id: f7644214-0eb0-4ace-9455-331ec4c09253
status: test
description: This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages
author: Florian Roth (Nextron Systems)
date: 2017/02/10
modified: 2021/11/27
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 675
            - 4768
            - 4769
            - 4771
        FailureCode:
            - '0x9'
            - '0xA'
            - '0xB'
            - '0xF'
            - '0x10'
            - '0x11'
            - '0x13'
            - '0x14'
            - '0x1A'
            - '0x1F'
            - '0x21'
            - '0x22'
            - '0x23'
            - '0x24'
            - '0x26'
            - '0x27'
            - '0x28'
            - '0x29'
            - '0x2C'
            - '0x2D'
            - '0x2E'
            - '0x2F'
            - '0x31'
            - '0x32'
            - '0x3E'
            - '0x3F'
            - '0x40'
            - '0x41'
            - '0x43'
            - '0x44'
    condition: selection
falsepositives:
    - Faulty legacy applications
level: high

```
