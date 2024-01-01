---
title: "Network Reconnaissance Activity"
status: "test"
created: "2022/02/07"
last_modified: ""
tags: [discovery, t1087, t1082, car_2016-03-001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Network Reconnaissance Activity

### Description

Detects a set of suspicious network related commands often used in recon stages

```yml
title: Network Reconnaissance Activity
id: e6313acd-208c-44fc-a0ff-db85d572e90e
status: test
description: Detects a set of suspicious network related commands often used in recon stages
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
author: Florian Roth (Nextron Systems)
date: 2022/02/07
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection_nslookup:
        CommandLine|contains|all:
            - 'nslookup'
            - '_ldap._tcp.dc._msdcs.'
    condition: 1 of selection*
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```
