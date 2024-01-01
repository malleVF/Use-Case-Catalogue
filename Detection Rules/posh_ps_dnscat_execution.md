---
title: "Dnscat Execution"
status: "test"
created: "2019/10/24"
last_modified: "2022/12/25"
tags: [exfiltration, t1048, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Dnscat Execution

### Description

Dnscat exfiltration tool execution

```yml
title: Dnscat Execution
id: a6d67db4-6220-436d-8afc-f3842fe05d43
status: test
description: Dnscat exfiltration tool execution
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2022/12/25
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'Start-Dnscat2'
    condition: selection
falsepositives:
    - Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)
level: critical

```
