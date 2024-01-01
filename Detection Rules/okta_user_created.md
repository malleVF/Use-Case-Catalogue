---
title: "New Okta User Created"
status: "experimental"
created: "2023/10/25"
last_modified: ""
tags: [credential_access, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "informational"
---

## New Okta User Created

### Description

Detects new user account creation

```yml
title: New Okta User Created
id: b6c718dd-8f53-4b9f-98d8-93fdca966969
status: experimental
description: Detects new user account creation
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/10/25
references:
    - https://developer.okta.com/docs/reference/api/event-types/
tags:
    - attack.credential_access
logsource:
    service: okta
    product: okta
detection:
    selection:
        eventtype: 'user.lifecycle.create'
    condition: selection
falsepositives:
    - Legitimate and authorized user creation
level: informational

```
