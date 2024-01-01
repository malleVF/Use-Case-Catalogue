---
title: "New Virtual Smart Card Created Via TpmVscMgr.EXE"
status: "experimental"
created: "2023/06/15"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New Virtual Smart Card Created Via TpmVscMgr.EXE

### Description

Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.

```yml
title: New Virtual Smart Card Created Via TpmVscMgr.EXE
id: c633622e-cab9-4eaa-bb13-66a1d68b3e47
status: experimental
description: Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.
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
        Image|endswith: '\tpmvscmgr.exe'
        OriginalFileName: 'TpmVscMgr.exe'
    selection_cli:
        CommandLine|contains: 'create'
    condition: all of selection_*
falsepositives:
    - Legitimate usage by an administrator
level: medium

```