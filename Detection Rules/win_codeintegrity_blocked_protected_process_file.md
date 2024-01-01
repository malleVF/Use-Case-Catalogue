---
title: "CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked"
status: "experimental"
created: "2023/06/06"
last_modified: ""
tags: [privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: "codeintegrity-operational"
level: "high"
---

## CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked

### Description

Detects block events for files that are disallowed by code integrity for protected processes

```yml
title: CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked
id: 5daf11c3-022b-4969-adb9-365e6c078c7c
status: experimental
description: Detects block events for files that are disallowed by code integrity for protected processes
references:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-id-explanations
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-tag-explanations
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/06/06
tags:
    - attack.privilege_escalation
logsource:
    product: windows
    service: codeintegrity-operational
detection:
    selection:
        EventID: 3104 # Windows blocked file %2 which has been disallowed for protected processes.
    condition: selection
falsepositives:
    - Unlikely
level: high

```
