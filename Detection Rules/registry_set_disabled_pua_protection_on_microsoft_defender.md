---
title: "Disable PUA Protection on Windows Defender"
status: "experimental"
created: "2021/08/04"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable PUA Protection on Windows Defender

### Description

Detects disabling Windows Defender PUA protection

```yml
title: Disable PUA Protection on Windows Defender
id: 8ffc5407-52e3-478f-9596-0a7371eafe13
status: experimental
description: Detects disabling Windows Defender PUA protection
references:
    - https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
author: Austin Songer @austinsonger
date: 2021/08/04
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Policies\Microsoft\Windows Defender\PUAProtection'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: high

```