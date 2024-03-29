---
title: "Psr.exe Capture Screenshots"
status: "test"
created: "2019/10/12"
last_modified: "2021/11/27"
tags: [collection, t1113, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Psr.exe Capture Screenshots

### Description

The psr.exe captures desktop screenshots and saves them on the local machine

```yml
title: Psr.exe Capture Screenshots
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: test
description: The psr.exe captures desktop screenshots and saves them on the local machine
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Psr/
    - https://web.archive.org/web/20200229201156/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493861893.pdf
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: Beyu Denis, oscd.community
date: 2019/10/12
modified: 2021/11/27
tags:
    - attack.collection
    - attack.t1113
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Psr.exe'
        CommandLine|contains: '/start'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
