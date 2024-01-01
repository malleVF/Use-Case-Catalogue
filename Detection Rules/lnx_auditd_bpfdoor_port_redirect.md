---
title: "Bpfdoor TCP Ports Redirect"
status: "test"
created: "2022/08/10"
last_modified: ""
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "medium"
---

## Bpfdoor TCP Ports Redirect

### Description

All TCP traffic on particular port from attacker is routed to different port. ex. '/sbin/iptables -t nat -D PREROUTING -p tcp -s 192.168.1.1 --dport 22 -j REDIRECT --to-ports 42392'
The traffic looks like encrypted SSH communications going to TCP port 22, but in reality is being directed to the shell port once it hits the iptables rule for the attacker host only.


```yml
title: Bpfdoor TCP Ports Redirect
id: 70b4156e-50fc-4523-aa50-c9dddf1993fc
status: test
description: |
    All TCP traffic on particular port from attacker is routed to different port. ex. '/sbin/iptables -t nat -D PREROUTING -p tcp -s 192.168.1.1 --dport 22 -j REDIRECT --to-ports 42392'
    The traffic looks like encrypted SSH communications going to TCP port 22, but in reality is being directed to the shell port once it hits the iptables rule for the attacker host only.
references:
    - https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
    - https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor
author: Rafal Piasecki
date: 2022/08/10
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    product: linux
    service: auditd
detection:
    cmd:
        type: 'EXECVE'
        a0|endswith: 'iptables'
        a1: '-t'
        a2: 'nat'
    keywords:
        - '--to-ports 42'
        - '--to-ports 43'
    condition: cmd and keywords
falsepositives:
    - Legitimate ports redirect
level: medium

```