---
title: "PowerShell Console History Logs Deleted"
status: "experimental"
created: "2023/02/15"
last_modified: ""
tags: [defense_evasion, t1070, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell Console History Logs Deleted

### Description

Detects the deletion of the PowerShell console History logs which may indicate an attempt to destroy forensic evidence

```yml
title: PowerShell Console History Logs Deleted
id: ff301988-c231-4bd0-834c-ac9d73b86586
status: experimental
description: Detects the deletion of the PowerShell console History logs which may indicate an attempt to destroy forensic evidence
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\PSReadLine\ConsoleHost_history.txt'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
