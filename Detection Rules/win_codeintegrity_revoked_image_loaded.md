---
title: "CodeIntegrity - Revoked Image Loaded"
status: "experimental"
created: "2023/06/06"
last_modified: ""
tags: [privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: "codeintegrity-operational"
level: "high"
---

## CodeIntegrity - Revoked Image Loaded

### Description

Detects image load events with revoked certificates by code integrity.

```yml
title: CodeIntegrity - Revoked Image Loaded
id: 881b7725-47cc-4055-8000-425823344c59
status: experimental
description: Detects image load events with revoked certificates by code integrity.
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
        EventID:
            - 3032 # Code Integrity determined a revoked image %2 is loaded into the system. Check with the publisher to see if a new signed version of the image is available.
            - 3035 # Code Integrity determined a revoked image %2 is loaded into the system. The image is allowed to load because kernel mode debugger is attached.
    condition: selection
falsepositives:
    - Unlikely
level: high

```