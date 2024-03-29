---
title: "Publicly Accessible RDP Service"
status: "test"
created: "2020/08/22"
last_modified: "2022/12/25"
tags: [lateral_movement, t1021_001, detection_rule]
logsrc_product: "zeek"
logsrc_service: "rdp"
level: "high"
---

## Publicly Accessible RDP Service

### Description

Detects connections from routable IPs to an RDP listener - which is indicative of a publicly-accessible RDP service.

```yml
title: Publicly Accessible RDP Service
id: 1fc0809e-06bf-4de3-ad52-25e5263b7623
status: test
description: Detects connections from routable IPs to an RDP listener - which is indicative of a publicly-accessible RDP service.
references:
    - https://attack.mitre.org/techniques/T1021/001/
author: 'Josh Brower @DefensiveDepth'
date: 2020/08/22
modified: 2022/12/25
tags:
    - attack.lateral_movement
    - attack.t1021.001
logsource:
    product: zeek
    service: rdp
detection:
    selection:
        id.orig_h|startswith:
            - '192.168.'
            - '10.'
            - '172.16.'
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - 'fd'
            - '2620:83:800f'
    # approved_rdp:
      # dst_ip:
        # - x.x.x.x
    condition: not selection # and not approved_rdp
falsepositives:
    - Although it is recommended to NOT have RDP exposed to the internet, verify that this is a) allowed b) the server has not already been compromised via some brute force or remote exploit since it has been exposed to the internet. Work to secure the server if you are unable to remove it from being exposed to the internet.
fields:
    - id.orig_h
    - id.resp_h
level: high

```
