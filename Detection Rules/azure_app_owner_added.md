---
title: "Added Owner To Application"
status: "test"
created: "2022/06/02"
last_modified: ""
tags: [t1552, credential_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## Added Owner To Application

### Description

Detects when a new owner is added to an application. This gives that account privileges to make modifications and configuration changes to the application.

```yml
title: Added Owner To Application
id: 74298991-9fc4-460e-a92e-511aa60baec1
status: test
description: Detects when a new owner is added to an application. This gives that account privileges to make modifications and configuration changes to the application.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#new-owner
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022/06/02
tags:
    - attack.t1552
    - attack.credential_access
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Add owner to application
    condition: selection
falsepositives:
    - When a new application owner is added by an administrator
level: medium

```
