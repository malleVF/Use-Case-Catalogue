---
title: "Rebuild Performance Counter Values Via Lodctr.EXE"
status: "experimental"
created: "2023/06/15"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Rebuild Performance Counter Values Via Lodctr.EXE

### Description

Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions.

```yml
title: Rebuild Performance Counter Values Via Lodctr.EXE
id: cc9d3712-6310-4320-b2df-7cb408274d53
status: experimental
description: Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions.
references:
    - https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/06/15
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\lodctr.exe'
        OriginalFileName: 'LODCTR.EXE'
    selection_cli:
        CommandLine|contains:
            - ' /r'
            - ' -r'
    condition: all of selection_*
falsepositives:
    - Legitimate usage by an administrator
level: medium

```
