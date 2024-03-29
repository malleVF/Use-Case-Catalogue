---
title: "Huawei BGP Authentication Failures"
status: "test"
created: "2023/01/09"
last_modified: "2023/01/23"
tags: [initial_access, persistence, privilege_escalation, defense_evasion, credential_access, collection, t1078, t1110, t1557, detection_rule]
logsrc_product: "huawei"
logsrc_service: "bgp"
level: "low"
---

## Huawei BGP Authentication Failures

### Description

Detects BGP failures which may be indicative of brute force attacks to manipulate routing.

```yml
title: Huawei BGP Authentication Failures
id: a557ffe6-ac54-43d2-ae69-158027082350
status: test
description: Detects BGP failures which may be indicative of brute force attacks to manipulate routing.
references:
    - https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf
author: Tim Brown
date: 2023/01/09
modified: 2023/01/23
tags:
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.credential_access
    - attack.collection
    - attack.t1078
    - attack.t1110
    - attack.t1557
logsource:
    product: huawei
    service: bgp
    definition: 'Requirements: huawei bgp logs need to be enabled and ingested'
detection:
    keywords_bgp_huawei:
        '|all':
            - ':179' # Protocol
            - 'BGP_AUTH_FAILED'
    condition: keywords_bgp_huawei
fields:
    - host
    - PeeId
falsepositives:
    - Unlikely. Except due to misconfigurations
level: low

```
