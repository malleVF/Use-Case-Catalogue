---
title: "BloodHound Collection Files"
status: "experimental"
created: "2022/08/09"
last_modified: "2023/03/29"
tags: [discovery, t1087_001, t1087_002, t1482, t1069_001, t1069_002, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## BloodHound Collection Files

### Description

Detects default file names outputted by the BloodHound collection tool SharpHound

```yml
title: BloodHound Collection Files
id: 02773bed-83bf-469f-b7ff-e676e7d78bab
status: experimental
description: Detects default file names outputted by the BloodHound collection tool SharpHound
references:
    - https://academy.hackthebox.com/course/preview/active-directory-bloodhound/bloodhound--data-collection
author: C.J. May
date: 2022/08/09
modified: 2023/03/29
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'BloodHound.zip'
            - '_computers.json'
            - '_containers.json'
            - '_domains.json'
            - '_gpos.json'
            - '_groups.json'
            - '_ous.json'
            - '_users.json'
    filter_optional_ms_winapps:
        Image|endswith: '\svchost.exe'
        TargetFilename|startswith: 'C:\Program Files\WindowsApps\Microsoft.'
        TargetFilename|endswith: '\pocket_containers.json'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise
level: high

```
