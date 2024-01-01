---
title: "Flash Player Update from Suspicious Location"
status: "test"
created: "2017/10/25"
last_modified: "2022/08/08"
tags: [initial_access, t1189, execution, t1204_002, defense_evasion, t1036_005, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Flash Player Update from Suspicious Location

### Description

Detects a flashplayer update from an unofficial location

```yml
title: Flash Player Update from Suspicious Location
id: 4922a5dd-6743-4fc2-8e81-144374280997
status: test
description: Detects a flashplayer update from an unofficial location
references:
    - https://gist.github.com/roycewilliams/a723aaf8a6ac3ba4f817847610935cfb
author: Florian Roth (Nextron Systems)
date: 2017/10/25
modified: 2022/08/08
tags:
    - attack.initial_access
    - attack.t1189
    - attack.execution
    - attack.t1204.002
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: proxy
detection:
    selection:
        - c-uri|contains: '/flash_install.php'
        - c-uri|endswith: '/install_flash_player.exe'
    filter:
        cs-host|endswith: '.adobe.com'
    condition: selection and not filter
falsepositives:
    - Unknown flash download locations
level: high

```
