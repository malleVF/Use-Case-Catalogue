---
title: "CodeIntegrity - Unsigned Image Loaded"
status: "experimental"
created: "2023/06/06"
last_modified: ""
tags: [privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: "codeintegrity-operational"
level: "high"
---

## CodeIntegrity - Unsigned Image Loaded

### Description

Detects loaded unsigned image on the system

```yml
title: CodeIntegrity - Unsigned Image Loaded
id: c92c24e7-f595-493f-9c98-53d5142f5c18
status: experimental
description: Detects loaded unsigned image on the system
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
        EventID: 3037 # Code Integrity determined an unsigned image %2 is loaded into the system. Check with the publisher to see if a signed version of the image is available.
    condition: selection
falsepositives:
    - Unlikely
level: high

```