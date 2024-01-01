---
title: "Potential Ransomware Activity Using LegalNotice Message"
status: "experimental"
created: "2022/12/11"
last_modified: "2023/08/17"
tags: [impact, t1491_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Ransomware Activity Using LegalNotice Message

### Description

Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages

```yml
title: Potential Ransomware Activity Using LegalNotice Message
id: 8b9606c9-28be-4a38-b146-0e313cc232c1
status: experimental
description: Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1491.001/T1491.001.md
author: frack113
date: 2022/12/11
modified: 2023/08/17
tags:
    - attack.impact
    - attack.t1491.001
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText'
        Details|contains:
            - 'encrypted'
            - 'Unlock-Password'
            - 'paying'
    condition: selection
falsepositives:
    - Unknown
level: high

```