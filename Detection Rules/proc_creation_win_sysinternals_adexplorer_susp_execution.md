---
title: "Suspicious Active Directory Database Snapshot Via ADExplorer"
status: "experimental"
created: "2023/03/14"
last_modified: ""
tags: [credential_access, t1552_001, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Active Directory Database Snapshot Via ADExplorer

### Description

Detects the execution of Sysinternals ADExplorer with the "-snapshot" flag in order to save a local copy of the active directory database to a suspicious directory.

```yml
title: Suspicious Active Directory Database Snapshot Via ADExplorer
id: ef61af62-bc74-4f58-b49b-626448227652
related:
    - id: 9212f354-7775-4e28-9c9f-8f0a4544e664
      type: derived
status: experimental
description: Detects the execution of Sysinternals ADExplorer with the "-snapshot" flag in order to save a local copy of the active directory database to a suspicious directory.
references:
    - https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/14
tags:
    - attack.credential_access
    - attack.t1552.001
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ADExplorer.exe'
        - OriginalFileName: 'AdExp'
    selection_flag:
        CommandLine|contains: 'snapshot'
    selection_paths:
        CommandLine|contains:
            # TODO: Add more suspicious paths
            - '\Downloads\'
            - '\Users\Public\'
            - '\AppData\'
            - '\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
