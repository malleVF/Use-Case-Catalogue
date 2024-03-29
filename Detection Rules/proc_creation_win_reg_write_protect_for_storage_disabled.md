---
title: "Write Protect For Storage Disabled"
status: "test"
created: "2021/06/11"
last_modified: "2023/12/15"
tags: [defense_evasion, t1562, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Write Protect For Storage Disabled

### Description

Looks for changes to registry to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.

```yml
title: Write Protect For Storage Disabled
id: 75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13
status: test
description: Looks for changes to registry to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.
author: Sreeman
date: 2021/06/11
modified: 2023/12/15
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Control'
            - 'Write Protection'
            - '0'
        CommandLine|contains:
            - 'storage'
            - 'storagedevicepolicies'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
