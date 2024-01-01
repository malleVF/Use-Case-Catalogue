---
title: "Apt GTFOBin Abuse - Linux"
status: "test"
created: "2022/12/28"
last_modified: ""
tags: [discovery, t1083, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Apt GTFOBin Abuse - Linux

### Description

Detects usage of "apt" and "apt-get" as a GTFOBin to execute and proxy command and binary execution

```yml
title: Apt GTFOBin Abuse - Linux
id: bb382fd5-b454-47ea-a264-1828e4c766d6
status: test
description: Detects usage of "apt" and "apt-get" as a GTFOBin to execute and proxy command and binary execution
references:
    - https://gtfobins.github.io/gtfobins/apt/
    - https://gtfobins.github.io/gtfobins/apt-get/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/28
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains: 'APT::Update::Pre-Invoke::='
    condition: selection
falsepositives:
    - Unknown
level: medium

```
