---
title: "Disable System Firewall"
status: "test"
created: "2022/01/22"
last_modified: ""
tags: [t1562_004, defense_evasion, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## Disable System Firewall

### Description

Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.

```yml
title: Disable System Firewall
id: 53059bc0-1472-438b-956a-7508a94a91f0
status: test
description: Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
    - https://firewalld.org/documentation/man-pages/firewall-cmd.html
author: 'Pawel Mazur'
date: 2022/01/22
tags:
    - attack.t1562.004
    - attack.defense_evasion
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SERVICE_STOP'
        unit:
            - 'firewalld'
            - 'iptables'
            - 'ufw'
    condition: selection
falsepositives:
    - Admin activity
level: high

```
