---
title: "Execute Pcwrun.EXE To Leverage Follina"
status: "test"
created: "2022/06/13"
last_modified: ""
tags: [defense_evasion, t1218, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Execute Pcwrun.EXE To Leverage Follina

### Description

Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability

```yml
title: Execute Pcwrun.EXE To Leverage Follina
id: 6004abd0-afa4-4557-ba90-49d172e0a299
status: test
description: Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability
references:
    - https://twitter.com/nas_bench/status/1535663791362519040
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/13
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pcwrun.exe'
        CommandLine|contains: '../'
    condition: selection
falsepositives:
    - Unlikely
level: high

```