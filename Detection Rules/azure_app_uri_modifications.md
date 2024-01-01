---
title: "Application URI Configuration Changes"
status: "test"
created: "2022/06/02"
last_modified: ""
tags: [t1528, t1078_004, persistence, credential_access, privilege_escalation, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Application URI Configuration Changes

### Description

Detects when a configuration change is made to an applications URI.
URIs for domain names that no longer exist (dangling URIs), not using HTTPS, wildcards at the end of the domain, URIs that are no unique to that app, or URIs that point to domains you do not control should be investigated.


```yml
title: Application URI Configuration Changes
id: 0055ad1f-be85-4798-83cf-a6da17c993b3
status: test
description: |
    Detects when a configuration change is made to an applications URI.
    URIs for domain names that no longer exist (dangling URIs), not using HTTPS, wildcards at the end of the domain, URIs that are no unique to that app, or URIs that point to domains you do not control should be investigated.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#application-configuration-changes
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022/06/02
tags:
    - attack.t1528
    - attack.t1078.004
    - attack.persistence
    - attack.credential_access
    - attack.privilege_escalation
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Update Application Sucess- Property Name AppAddress
    condition: selection
falsepositives:
    - When and administrator is making legitimate URI configuration changes to an application. This should be a planned event.
level: high

```
