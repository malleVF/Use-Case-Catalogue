---
title: "Suspicious C2 Activities"
status: "test"
created: "2020/05/18"
last_modified: "2021/11/27"
tags: [command_and_control, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "medium"
---

## Suspicious C2 Activities

### Description

Detects suspicious activities as declared by Florian Roth in its 'Best Practice Auditd Configuration'.
This includes the detection of the following commands; wget, curl, base64, nc, netcat, ncat, ssh, socat, wireshark, rawshark, rdesktop, nmap.
These commands match a few techniques from the tactics "Command and Control", including not exhaustively the following; Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095), Data Encoding (T1132)


```yml
title: Suspicious C2 Activities
id: f7158a64-6204-4d6d-868a-6e6378b467e0
status: test
description: |
    Detects suspicious activities as declared by Florian Roth in its 'Best Practice Auditd Configuration'.
    This includes the detection of the following commands; wget, curl, base64, nc, netcat, ncat, ssh, socat, wireshark, rawshark, rdesktop, nmap.
    These commands match a few techniques from the tactics "Command and Control", including not exhaustively the following; Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095), Data Encoding (T1132)
references:
    - https://github.com/Neo23x0/auditd
author: Marie Euler
date: 2020/05/18
modified: 2021/11/27
tags:
    - attack.command_and_control
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key: 'susp_activity'
    condition: selection
falsepositives:
    - Admin or User activity
level: medium

```
