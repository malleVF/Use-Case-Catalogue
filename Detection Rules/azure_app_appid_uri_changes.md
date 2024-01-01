---
title: "Application AppID Uri Configuration Changes"
status: "test"
created: "2022/06/02"
last_modified: ""
tags: [persistence, credential_access, privilege_escalation, t1552, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Application AppID Uri Configuration Changes

### Description

Detects when a configuration change is made to an applications AppID URI.

```yml
title: Application AppID Uri Configuration Changes
id: 1b45b0d1-773f-4f23-aedc-814b759563b1
status: test
description: Detects when a configuration change is made to an applications AppID URI.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#appid-uri-added-modified-or-removed
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022/06/02
tags:
    - attack.persistence
    - attack.credential_access
    - attack.privilege_escalation
    - attack.t1552
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Update Application
            - Update Service principal
    condition: selection
falsepositives:
    - When and administrator is making legitimate AppID URI configuration changes to an application. This should be a planned event.
level: high

```
