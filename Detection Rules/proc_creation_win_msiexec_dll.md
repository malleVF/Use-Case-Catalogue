---
title: "DllUnregisterServer Function Call Via Msiexec.EXE"
status: "experimental"
created: "2022/04/24"
last_modified: "2023/02/22"
tags: [defense_evasion, t1218_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## DllUnregisterServer Function Call Via Msiexec.EXE

### Description

Detects MsiExec loading a DLL and calling its DllUnregisterServer function

```yml
title: DllUnregisterServer Function Call Via Msiexec.EXE
id: 84f52741-8834-4a8c-a413-2eb2269aa6c8
status: experimental
description: Detects MsiExec loading a DLL and calling its DllUnregisterServer function
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
    - https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
    - https://twitter.com/_st0pp3r_/status/1583914515996897281
author: frack113
date: 2022/04/24
modified: 2023/02/22
tags:
    - attack.defense_evasion
    - attack.t1218.007
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\msiexec.exe'
        - OriginalFileName: '\msiexec.exe'
    selection_flag:
        CommandLine|contains:
            - ' /z '
            - ' -z '
    selection_dll:
        CommandLine|contains: '.dll'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```