---
title: "Modification of Explorer Hidden Keys"
status: "experimental"
created: "2022/04/02"
last_modified: "2023/08/17"
tags: [defense_evasion, t1564_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Modification of Explorer Hidden Keys

### Description

Detects modifications to the hidden files keys in registry. This technique is abused by several malware families to hide their files from normal users.

```yml
title: Modification of Explorer Hidden Keys
id: 5a5152f1-463f-436b-b2f5-8eceb3964b42
status: experimental
description: Detects modifications to the hidden files keys in registry. This technique is abused by several malware families to hide their files from normal users.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md#atomic-test-8---hide-files-through-registry
author: frack113
date: 2022/04/02
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1564.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject:
            - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden
            - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
