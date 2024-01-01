---
title: "ESXi Syslog Configuration Change Via ESXCLI"
status: "experimental"
created: "2023/09/04"
last_modified: ""
tags: [defense_evasion, t1562_001, t1562_003, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## ESXi Syslog Configuration Change Via ESXCLI

### Description

Detects changes to the ESXi syslog configuration via "esxcli"

```yml
title: ESXi Syslog Configuration Change Via ESXCLI
id: 38eb1dbb-011f-40b1-a126-cf03a0210563
status: experimental
description: Detects changes to the ESXi syslog configuration via "esxcli"
references:
    - https://support.solarwinds.com/SuccessCenter/s/article/Configure-ESXi-Syslog-to-LEM?language=en_US
    - https://developer.vmware.com/docs/11743/esxi-7-0-esxcli-command-reference/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023/09/04
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1562.003
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system'
            - 'syslog'
            - 'config'
        CommandLine|contains: ' set'
    condition: selection
falsepositives:
    - Legitimate administrative activities
level: medium

```
