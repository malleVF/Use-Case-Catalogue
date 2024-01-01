---
title: "Added Credentials to Existing Application"
status: "test"
created: "2022/05/26"
last_modified: ""
tags: [t1098_001, persistence, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Added Credentials to Existing Application

### Description

Detects when a new credential is added to an existing application. Any additional credentials added outside of expected processes could be a malicious actor using those credentials.

```yml
title: Added Credentials to Existing Application
id: cbb67ecc-fb70-4467-9350-c910bdf7c628
status: test
description: Detects when a new credential is added to an existing application. Any additional credentials added outside of expected processes could be a malicious actor using those credentials.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#application-credentials
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022/05/26
tags:
    - attack.t1098.001
    - attack.persistence
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Update Application-Certificates and secrets management
            - Update Service principal/Update Application
    condition: selection
falsepositives:
    - When credentials are added/removed as part of the normal working hours/workflows
level: high

```
