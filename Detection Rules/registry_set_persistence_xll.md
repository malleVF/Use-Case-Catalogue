---
title: "Potential Persistence Via Excel Add-in - Registry"
status: "experimental"
created: "2023/01/15"
last_modified: "2023/08/17"
tags: [persistence, t1137_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Persistence Via Excel Add-in - Registry

### Description

Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.

```yml
title: Potential Persistence Via Excel Add-in - Registry
id: 961e33d1-4f86-4fcf-80ab-930a708b2f82
status: experimental
description: Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/4ae9580a1a8772db87a1b6cdb0d03e5af231e966/atomics/T1137.006/T1137.006.md
    - https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence
author: frack113
date: 2023/01/15
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.t1137.006
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: 'Software\Microsoft\Office\'
        TargetObject|endswith: '\Excel\Options'
        Details|startswith: '/R '
        Details|endswith: '.xll'
    condition: selection
falsepositives:
    - Unknown
level: high

```