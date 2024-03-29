---
title: "Local User Creation"
status: "test"
created: "2019/04/18"
last_modified: "2021/01/17"
tags: [persistence, t1136_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Local User Creation

### Description

Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.

```yml
title: Local User Creation
id: 66b6be3d-55d0-4f47-9855-d69df21740ea
status: test
description: Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.
references:
    - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/
author: Patrick Bareiss
date: 2019/04/18
modified: 2021/01/17
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
fields:
    - EventCode
    - AccountName
    - AccountDomain
falsepositives:
    - Domain Controller Logs
    - Local accounts managed by privileged account management tools
level: low

```
