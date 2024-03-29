---
title: "Okta Identity Provider Created"
status: "experimental"
created: "2023/09/07"
last_modified: ""
tags: [persistence, t1098_001, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Identity Provider Created

### Description

Detects when a new identity provider is created for Okta.

```yml
title: Okta Identity Provider Created
id: 969c7590-8c19-4797-8c1b-23155de6e7ac
status: experimental
description: Detects when a new identity provider is created for Okta.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
author: kelnage
date: 2023/09/07
tags:
    - attack.persistence
    - attack.t1098.001
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype: 'system.idp.lifecycle.create'
    condition: selection
falsepositives:
    - When an admin creates a new, authorised identity provider.
level: medium

```
