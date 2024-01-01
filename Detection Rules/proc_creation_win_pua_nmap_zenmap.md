---
title: "PUA - Nmap/Zenmap Execution"
status: "test"
created: "2021/12/10"
last_modified: "2023/12/11"
tags: [discovery, t1046, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - Nmap/Zenmap Execution

### Description

Detects usage of namp/zenmap. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation

```yml
title: PUA - Nmap/Zenmap Execution
id: f6ecd1cf-19b8-4488-97f6-00f0924991a3
status: test
description: Detects usage of namp/zenmap. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation
references:
    - https://nmap.org/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md#atomic-test-3---port-scan-nmap-for-windows
author: frack113
date: 2021/12/10
modified: 2023/12/11
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\nmap.exe'
              - '\zennmap.exe'
        - OriginalFileName:
              - 'nmap.exe'
              - 'zennmap.exe'
    condition: selection
falsepositives:
    - Legitimate administrator activity
level: medium

```