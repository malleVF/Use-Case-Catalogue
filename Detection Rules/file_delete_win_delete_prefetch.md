---
title: "Prefetch File Deleted"
status: "experimental"
created: "2021/09/29"
last_modified: "2023/02/15"
tags: [defense_evasion, t1070_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Prefetch File Deleted

### Description

Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence

```yml
title: Prefetch File Deleted
id: 0a1f9d29-6465-4776-b091-7f43b26e4c89
status: experimental
description: Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence
author: Cedric MAURUGEON
date: 2021/09/29
modified: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\Prefetch\'
        TargetFilename|endswith: '.pf'
    filter:
        Image: 'C:\windows\system32\svchost.exe'
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
