---
title: "Juniper BGP Missing MD5"
status: "test"
created: "2023/01/09"
last_modified: "2023/01/23"
tags: [initial_access, persistence, privilege_escalation, defense_evasion, credential_access, collection, t1078, t1110, t1557, detection_rule]
logsrc_product: "juniper"
logsrc_service: "bgp"
level: "low"
---

## Juniper BGP Missing MD5

### Description

Detects juniper BGP missing MD5 digest. Which may be indicative of brute force attacks to manipulate routing.

```yml
title: Juniper BGP Missing MD5
id: a7c0ae48-8df8-42bf-91bd-2ea57e2f9d43
status: test
description: Detects juniper BGP missing MD5 digest. Which may be indicative of brute force attacks to manipulate routing.
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
    product: juniper
    service: bgp
    definition: 'Requirements: juniper bgp logs need to be enabled and ingested'
detection:
    keywords_bgp_juniper:
        '|all':
            - ':179' # Protocol
            - 'missing MD5 digest'
    condition: keywords_bgp_juniper
fields:
    - host
falsepositives:
    - Unlikely. Except due to misconfigurations
level: low

```
