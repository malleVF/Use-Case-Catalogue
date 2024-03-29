---
title: "Okta New Admin Console Behaviours"
status: "experimental"
created: "2023/09/07"
last_modified: "2023/10/25"
tags: [initial_access, t1078_004, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "low"
---

## Okta New Admin Console Behaviours

### Description

Detects when Okta identifies new activity in the Admin Console.

```yml
title: Okta New Admin Console Behaviours
id: a0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9
status: experimental
description: Detects when Okta identifies new activity in the Admin Console.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
author: kelnage
date: 2023/09/07
modified: 2023/10/25
tags:
    - attack.initial_access
    - attack.t1078.004
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype: 'policy.evaluate_sign_on'
        target.displayname: 'Okta Admin Console'
        debugcontext.debugdata.behaviors: 'POSITIVE'
        debugcontext.debugdata.logonlysecuritydata: 'POSITIVE'
    condition: selection
falsepositives:
    - Whenever an admin starts using new features of the admin console.
level: low

```
