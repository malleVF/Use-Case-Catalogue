---
title: "Potential NTLM Coercion Via Certutil.EXE"
status: "experimental"
created: "2022/09/01"
last_modified: "2023/02/14"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential NTLM Coercion Via Certutil.EXE

### Description

Detects possible NTLM coercion via certutil using the 'syncwithWU' flag

```yml
title: Potential NTLM Coercion Via Certutil.EXE
id: 6c6d9280-e6d0-4b9d-80ac-254701b64916
status: experimental
description: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
references:
    - https://github.com/LOLBAS-Project/LOLBAS/issues/243
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/01
modified: 2023/02/14
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' -syncwithWU '
            - ' \\\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
