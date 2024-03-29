---
title: "Triple Cross eBPF Rootkit Install Commands"
status: "test"
created: "2022/07/05"
last_modified: ""
tags: [defense_evasion, t1014, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Triple Cross eBPF Rootkit Install Commands

### Description

Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script

```yml
title: Triple Cross eBPF Rootkit Install Commands
id: 22236d75-d5a0-4287-bf06-c93b1770860f
status: test
description: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/05
tags:
    - attack.defense_evasion
    - attack.t1014
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains|all:
            - ' tc '
            - ' enp0s3 '
        CommandLine|contains:
            - ' qdisc '
            - ' filter '
    condition: selection
falsepositives:
    - Unlikely
level: high

```
