---
title: "Script Initiated Connection to Non-Local Network"
status: "test"
created: "2022/08/28"
last_modified: ""
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Script Initiated Connection to Non-Local Network

### Description

Detects a script interpreter wscript/cscript opening a network connection to a non-local network. Adversaries may use script to download malicious payloads.

```yml
title: Script Initiated Connection to Non-Local Network
id: 992a6cae-db6a-43c8-9cec-76d7195c96fc
status: test
description: Detects a script interpreter wscript/cscript opening a network connection to a non-local network. Adversaries may use script to download malicious payloads.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/28d190330fe44de6ff4767fc400cc10fa7cd6540/atomics/T1105/T1105.md
author: frack113, Florian Roth
date: 2022/08/28
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    filter_lan:
        DestinationIp|startswith:
            - '127.'
            - '10.'
            - '172.'
            - '192.'
            - '169.254.' # 169.254.0.0/16
            - '20.'  # Microsoft Range
    filter_ipv6:
        DestinationIp|startswith:
            - '::1'  # IPv6 loopback variant
            - '0:0:0:0:0:0:0:1'  # IPv6 loopback variant
            - 'fe80:'  # link-local address
            - 'fc'  # private address range fc00::/7
            - 'fd'  # private address range fc00::/7
#    filter_lan_cidr:
#        DestinationIp|cidr:
#            - '127.0.0.0/8'
#            - '10.0.0.0/8'
#            - '172.16.0.0/12'
#            - '192.168.0.0/16'
    condition: selection and not 1 of filter*
falsepositives:
    - Legitimate scripts
level: high

```
