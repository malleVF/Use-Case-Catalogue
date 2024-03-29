---
title: "Okta FastPass Phishing Detection"
status: "experimental"
created: "2023/05/07"
last_modified: ""
tags: [initial_access, t1566, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "high"
---

## Okta FastPass Phishing Detection

### Description

Detects when Okta FastPass prevents a known phishing site.

```yml
title: Okta FastPass Phishing Detection
id: ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e
status: experimental
description: Detects when Okta FastPass prevents a known phishing site.
references:
    - https://sec.okta.com/fastpassphishingdetection
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2023/05/07
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    product: okta
    service: okta
detection:
    selection:
        outcome.reason: 'FastPass declined phishing attempt'
        outcome.result: FAILURE
        eventtype: user.authentication.auth_via_mfa
    condition: selection
falsepositives:
    - Unlikely
level: high

```
