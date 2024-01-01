---
title: "New Network Trace Capture Started Via Netsh.EXE"
status: "test"
created: "2019/10/24"
last_modified: "2023/02/13"
tags: [discovery, credential_access, t1040, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New Network Trace Capture Started Via Netsh.EXE

### Description

Detects the execution of netsh with the "trace" flag in order to start a network capture

```yml
title: New Network Trace Capture Started Via Netsh.EXE
id: d3c3861d-c504-4c77-ba55-224ba82d0118
status: test
description: Detects the execution of netsh with the "trace" flag in order to start a network capture
references:
    - https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
    - https://klausjochem.me/2016/02/03/netsh-the-cyber-attackers-tool-of-choice/
author: Kutepov Anton, oscd.community
date: 2019/10/24
modified: 2023/02/13
tags:
    - attack.discovery
    - attack.credential_access
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'trace'
            - 'start'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activity
level: medium

```