---
title: "Suspicious Tasklist Discovery Command"
status: "test"
created: "2021/12/11"
last_modified: "2022/12/25"
tags: [discovery, t1057, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "informational"
---

## Suspicious Tasklist Discovery Command

### Description

Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network

```yml
title: Suspicious Tasklist Discovery Command
id: 63332011-f057-496c-ad8d-d2b6afb27f96
status: test
description: Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1057/T1057.md#atomic-test-2---process-discovery---tasklist
author: frack113
date: 2021/12/11
modified: 2022/12/25
tags:
    - attack.discovery
    - attack.t1057
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: 'tasklist'
        - Image|endswith: '\tasklist.exe'
        - OriginalFileName: 'tasklist.exe'
    condition: selection
falsepositives:
    - Administrator, hotline ask to user
level: informational

```
