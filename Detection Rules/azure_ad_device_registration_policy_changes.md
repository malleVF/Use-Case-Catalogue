---
title: "Changes to Device Registration Policy"
status: "test"
created: "2022/06/28"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1484, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Changes to Device Registration Policy

### Description

Monitor and alert for changes to the device registration policy.

```yml
title: Changes to Device Registration Policy
id: 9494bff8-959f-4440-bbce-fb87a208d517
status: test
description: Monitor and alert for changes to the device registration policy.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-devices#device-registrations-and-joins-outside-policy
author: Michael Epping, '@mepples21'
date: 2022/06/28
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1484
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: 'Policy'
        ActivityDisplayName: 'Set device registration policies'
    condition: selection
falsepositives:
    - Unknown
level: high

```
