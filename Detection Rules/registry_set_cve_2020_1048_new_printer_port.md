---
title: "Suspicious New Printer Ports in Registry (CVE-2020-1048)"
status: "test"
created: "2020/05/13"
last_modified: "2023/08/17"
tags: [persistence, execution, defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious New Printer Ports in Registry (CVE-2020-1048)

### Description

Detects a new and suspicious printer port creation in Registry that could be an attempt to exploit CVE-2020-1048

```yml
title: Suspicious New Printer Ports in Registry (CVE-2020-1048)
id: 7ec912f2-5175-4868-b811-ec13ad0f8567
status: test
description: Detects a new and suspicious printer port creation in Registry that could be an attempt to exploit CVE-2020-1048
references:
    - https://windows-internals.com/printdemon-cve-2020-1048/
author: EagleEye Team, Florian Roth (Nextron Systems), NVISO
date: 2020/05/13
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.execution
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports'
        Details|contains:
            - '.dll'
            - '.exe'
            - '.bat'
            - '.com'
            - 'C:'
    condition: selection
falsepositives:
    - New printer port install on host
level: high

```
