---
title: "Root Account Enable Via Dsenableroot"
status: "experimental"
created: "2023/08/22"
last_modified: ""
tags: [t1078, t1078_001, t1078_003, initial_access, persistence, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## Root Account Enable Via Dsenableroot

### Description

Detects attempts to enable the root account via "dsenableroot"

```yml
title: Root Account Enable Via Dsenableroot
id: 821bcf4d-46c7-4b87-bc57-9509d3ba7c11
status: experimental
description: Detects attempts to enable the root account via "dsenableroot"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1078.003/T1078.003.md
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/persistence_enable_root_account.toml
    - https://ss64.com/osx/dsenableroot.html
author: Sohan G (D4rkCiph3r)
date: 2023/08/22
tags:
    - attack.t1078
    - attack.t1078.001
    - attack.t1078.003
    - attack.initial_access
    - attack.persistence
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/dsenableroot'
    filter_main_disable:
        CommandLine|contains: ' -d '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```
