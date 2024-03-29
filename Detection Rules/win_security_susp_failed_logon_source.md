---
title: "Failed Logon From Public IP"
status: "test"
created: "2020/05/06"
last_modified: "2023/01/11"
tags: [initial_access, persistence, t1078, t1190, t1133, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Failed Logon From Public IP

### Description

A login from a public IP can indicate a misconfigured firewall or network boundary.

```yml
title: Failed Logon From Public IP
id: f88e112a-21aa-44bd-9b01-6ee2a2bbbed1
status: test
description: A login from a public IP can indicate a misconfigured firewall or network boundary.
author: NVISO
date: 2020/05/06
modified: 2023/01/11
tags:
    - attack.initial_access
    - attack.persistence
    - attack.t1078
    - attack.t1190
    - attack.t1133
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    filter_ip_unknown:
        IpAddress|contains: '-'
    filter_ip_privatev4:
        IpAddress|startswith:
            - '10.' # 10.0.0.0/8
            - '192.168.' # 192.168.0.0/16
            - '172.16.' # 172.16.0.0/12
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
            - '127.' # 127.0.0.0/8
            - '169.254.' # 169.254.0.0/16
    filter_ip_privatev6:
        - IpAddress: '::1' # loopback
        - IpAddress|startswith:
              - 'fe80::' # link-local
              - 'fc00::' # unique local
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate logon attempts over the internet
    - IPv4-to-IPv6 mapped IPs
level: medium

```
