---
title: "Dllhost Internet Connection"
status: "test"
created: "2020/07/13"
last_modified: "2023/01/20"
tags: [defense_evasion, t1218, execution, t1559_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Dllhost Internet Connection

### Description

Detects Dllhost that communicates with public IP addresses

```yml
title: Dllhost Internet Connection
id: cfed2f44-16df-4bf3-833a-79405198b277
status: test
description: Detects Dllhost that communicates with public IP addresses
references:
    - https://redcanary.com/blog/child-processes/
    - https://nasbench.medium.com/what-is-the-dllhost-exe-process-actually-running-ef9fe4c19c08
author: bartblaze
date: 2020/07/13
modified: 2023/01/20
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution
    - attack.t1559.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\dllhost.exe'
        Initiated: 'true'
    filter_ipv4:
        DestinationIp|startswith:
            - '10.'
            - '192.168.'
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
            - '169.254.'  # link-local address
            - '127.'  # loopback address
    filter_ipv6:
        DestinationIp|startswith:
            - '::1'  # IPv6 loopback variant
            - '0:0:0:0:0:0:0:1'  # IPv6 loopback variant
            - 'fe80:'  # link-local address
            - 'fc'  # private address range fc00::/7
            - 'fd'  # private address range fc00::/7
    filter_msrange:
        DestinationIp|startswith:
            # Subnet: 20.184.0.0/13
            - '20.184.'
            - '20.185.'
            - '20.186.'
            - '20.187.'
            - '20.188.'
            - '20.189.'
            - '20.190.'
            - '20.191.'
            - '23.79.'
            - '51.10.'
            # Subnet: 51.103.210.0/23
            - '51.103.'
            - '51.104.'
            - '51.105.'
            - '52.239.'
    condition: selection and not 1 of filter_*
falsepositives:
    - Communication to other corporate systems that use IP addresses from public address spaces
level: medium

```
