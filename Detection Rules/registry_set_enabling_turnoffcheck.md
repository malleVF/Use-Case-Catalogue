---
title: "Scripted Diagnostics Turn Off Check Enabled - Registry"
status: "experimental"
created: "2022/06/15"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Scripted Diagnostics Turn Off Check Enabled - Registry

### Description

Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability

```yml
title: Scripted Diagnostics Turn Off Check Enabled - Registry
id: 7d995e63-ec83-4aa3-89d5-8a17b5c87c86
status: experimental
description: Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability
references:
    - https://twitter.com/wdormann/status/1537075968568877057?s=20&t=0lr18OAnmAGoGpma6grLUw
author: 'Christopher Peacock @securepeacock, SCYTHE @scythe_io'
date: 2022/06/15
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: '\Policies\Microsoft\Windows\ScriptedDiagnostics\TurnOffCheck'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Administrator actions
level: medium

```
