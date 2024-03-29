---
title: "NetNTLM Downgrade Attack - Registry"
status: "test"
created: "2018/03/20"
last_modified: "2022/11/29"
tags: [defense_evasion, t1562_001, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## NetNTLM Downgrade Attack - Registry

### Description

Detects NetNTLM downgrade attack

```yml
title: NetNTLM Downgrade Attack - Registry
id: d67572a0-e2ec-45d6-b8db-c100d14b8ef2
status: test
description: Detects NetNTLM downgrade attack
references:
    - https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
author: Florian Roth (Nextron Systems), wagga
date: 2018/03/20
modified: 2022/11/29
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains|all:
            - 'SYSTEM\'
            - 'ControlSet'
            - '\Control\Lsa'
        TargetObject|endswith:
            - '\lmcompatibilitylevel'
            - '\NtlmMinClientSec'
            - '\RestrictSendingNTLMTraffic'
    condition: selection
falsepositives:
    - Unknown
level: high

```
