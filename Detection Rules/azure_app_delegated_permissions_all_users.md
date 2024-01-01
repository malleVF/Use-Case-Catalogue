---
title: "Delegated Permissions Granted For All Users"
status: "test"
created: "2022/07/28"
last_modified: ""
tags: [credential_access, t1528, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Delegated Permissions Granted For All Users

### Description

Detects when highly privileged delegated permissions are granted on behalf of all users

```yml
title: Delegated Permissions Granted For All Users
id: a6355fbe-f36f-45d8-8efc-ab42465cbc52
status: test
description: Detects when highly privileged delegated permissions are granted on behalf of all users
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#application-granted-highly-privileged-permissions
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022/07/28
tags:
    - attack.credential_access
    - attack.t1528
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Add delegated permission grant
    condition: selection
falsepositives:
    - When the permission is legitimately needed for the app
level: high

```
