---
title: "Lsass Full Dump Request Via DumpType Registry Settings"
status: "experimental"
created: "2022/12/08"
last_modified: "2023/08/17"
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Lsass Full Dump Request Via DumpType Registry Settings

### Description

Detects the setting of the "DumpType" registry value to "2" which stands for a "Full Dump". Technique such as LSASS Shtinkering requires this value to be "2" in order to dump LSASS.

```yml
title: Lsass Full Dump Request Via DumpType Registry Settings
id: 33efc23c-6ea2-4503-8cfe-bdf82ce8f719
status: experimental
description: Detects the setting of the "DumpType" registry value to "2" which stands for a "Full Dump". Technique such as LSASS Shtinkering requires this value to be "2" in order to dump LSASS.
references:
    - https://github.com/deepinstinct/Lsass-Shtinkering
    - https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
    - https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf
author: '@pbssubhash'
date: 2022/12/08
modified: 2023/08/17
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DumpType'
            - '\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe\DumpType'
        Details: 'DWORD (0x00000002)' # Full Dump
    condition: selection
falsepositives:
    - Legitimate application that needs to do a full dump of their process
level: high

```