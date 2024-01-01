---
title: "Suspicious New-PSDrive to Admin Share"
status: "test"
created: "2022/08/13"
last_modified: ""
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious New-PSDrive to Admin Share

### Description

Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

```yml
title: Suspicious New-PSDrive to Admin Share
id: 1c563233-030e-4a07-af8c-ee0490a66d3a
status: test
description: Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.002/T1021.002.md#atomic-test-2---map-admin-share-powershell
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.2
author: frack113
date: 2022/08/13
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'New-PSDrive'
            - '-psprovider '
            - 'filesystem'
            - '-root '
            - '\\\\'
            - '$'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
