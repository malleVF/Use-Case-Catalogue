---
title: "SMB Create Remote File Admin Share"
status: "test"
created: "2020/08/06"
last_modified: "2021/11/27"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## SMB Create Remote File Admin Share

### Description

Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).

```yml
title: SMB Create Remote File Admin Share
id: b210394c-ba12-4f89-9117-44a2464b9511
status: test
description: Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).
references:
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/f7a58156dbfc9b019f17f638b8c62d22e557d350/playbooks/WIN-201012004336.yaml
    - https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806015757.html?highlight=create%20file
author: Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)
date: 2020/08/06
modified: 2021/11/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName|endswith: 'C$'
        AccessMask: '0x2'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
