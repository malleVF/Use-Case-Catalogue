---
title: "BITS Transfer Job Download To Potential Suspicious Folder"
status: "experimental"
created: "2022/06/28"
last_modified: "2023/03/27"
tags: [defense_evasion, persistence, t1197, detection_rule]
logsrc_product: "windows"
logsrc_service: "bits-client"
level: "high"
---

## BITS Transfer Job Download To Potential Suspicious Folder

### Description

Detects new BITS transfer job where the LocalName/Saved file is stored in a potentially suspicious location

```yml
title: BITS Transfer Job Download To Potential Suspicious Folder
id: f8a56cb7-a363-44ed-a82f-5926bb44cd05
status: experimental
description: Detects new BITS transfer job where the LocalName/Saved file is stored in a potentially suspicious location
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
author: Florian Roth (Nextron Systems)
date: 2022/06/28
modified: 2023/03/27
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
logsource:
    product: windows
    service: bits-client
detection:
    selection:
        EventID: 16403
        LocalName|contains:
            # TODO: Add more interesting suspicious paths
            - '\Desktop\'
            - 'C:\Users\Public\'
            - 'C:\PerfLogs\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
