---
title: "Guest Account Enabled Via Sysadminctl"
status: "experimental"
created: "2023/02/18"
last_modified: ""
tags: [initial_access, t1078, t1078_001, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "low"
---

## Guest Account Enabled Via Sysadminctl

### Description

Detects attempts to enable the guest account using the sysadminctl utility

```yml
title: Guest Account Enabled Via Sysadminctl
id: d7329412-13bd-44ba-a072-3387f804a106
status: experimental
description: Detects attempts to enable the guest account using the sysadminctl utility
references:
    - https://ss64.com/osx/sysadminctl.html
author: Sohan G (D4rkCiph3r)
date: 2023/02/18
tags:
    - attack.initial_access
    - attack.t1078
    - attack.t1078.001
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/sysadminctl'
        CommandLine|contains|all:
            # By default the guest account is not active
            - ' -guestAccount'
            - ' on'
    condition: selection
falsepositives:
    - Unknown
level: low

```
