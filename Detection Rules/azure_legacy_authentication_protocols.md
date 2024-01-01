---
title: "Use of Legacy Authentication Protocols"
status: "test"
created: "2022/06/17"
last_modified: ""
tags: [initial_access, credential_access, t1078_004, t1110, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Use of Legacy Authentication Protocols

### Description

Alert on when legacy authentication has been used on an account

```yml
title: Use of Legacy Authentication Protocols
id: 60f6535a-760f-42a9-be3f-c9a0a025906e
status: test
description: Alert on when legacy authentication has been used on an account
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: Yochana Henderson, '@Yochana-H'
date: 2022/06/17
tags:
    - attack.initial_access
    - attack.credential_access
    - attack.t1078.004
    - attack.t1110
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ActivityDetails: Sign-ins
        ClientApp:
            - Other client
            - IMAP
            - POP3
            - MAPI
            - SMTP
            - Exchange ActiveSync
            - Exchange Web Services
        Username: 'UPN'
    condition: selection
falsepositives:
    - User has been put in acception group so they can use legacy authentication
level: high

```
