---
title: "Cisco LDP Authentication Failures"
status: "test"
created: "2023/01/09"
last_modified: ""
tags: [initial_access, persistence, privilege_escalation, defense_evasion, credential_access, collection, t1078, t1110, t1557, detection_rule]
logsrc_product: "cisco"
logsrc_service: "ldp"
level: "low"
---

## Cisco LDP Authentication Failures

### Description

Detects LDP failures which may be indicative of brute force attacks to manipulate MPLS labels

```yml
title: Cisco LDP Authentication Failures
id: 50e606bf-04ce-4ca7-9d54-3449494bbd4b
status: test
description: Detects LDP failures which may be indicative of brute force attacks to manipulate MPLS labels
references:
    - https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf
author: Tim Brown
date: 2023/01/09
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
    product: cisco
    service: ldp
    definition: 'Requirements: cisco ldp logs need to be enabled and ingested'
detection:
    selection_protocol:
        - 'LDP'
    selection_keywords:
        - 'SOCKET_TCP_PACKET_MD5_AUTHEN_FAIL'
        - 'TCPMD5AuthenFail'
    condition: selection_protocol and selection_keywords
fields:
    - tcpConnLocalAddress
    - tcpConnRemAddress
falsepositives:
    - Unlikely. Except due to misconfigurations
level: low

```
