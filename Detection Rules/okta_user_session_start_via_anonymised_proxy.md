---
title: "Okta User Session Start Via An Anonymising Proxy Service"
status: "experimental"
created: "2023/09/07"
last_modified: ""
tags: [defense_evasion, t1562_006, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "high"
---

## Okta User Session Start Via An Anonymising Proxy Service

### Description

Detects when an Okta user session starts where the user is behind an anonymising proxy service.

```yml
title: Okta User Session Start Via An Anonymising Proxy Service
id: bde30855-5c53-4c18-ae90-1ff79ebc9578
status: experimental
description: Detects when an Okta user session starts where the user is behind an anonymising proxy service.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
author: kelnage
date: 2023/09/07
tags:
    - attack.defense_evasion
    - attack.t1562.006
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype: 'user.session.start'
        securitycontext.isproxy: 'true'
    condition: selection
falsepositives:
    - If a user requires an anonymising proxy due to valid justifications.
level: high

```
