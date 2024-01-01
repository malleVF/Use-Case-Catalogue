---
title: "Potential Vivaldi_elf.DLL Sideloading"
status: "experimental"
created: "2023/08/03"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Vivaldi_elf.DLL Sideloading

### Description

Detects potential DLL sideloading of "vivaldi_elf.dll"

```yml
title: Potential Vivaldi_elf.DLL Sideloading
id: 2092cacb-d77b-4f98-ab0d-32b32f99a054
status: experimental
description: Detects potential DLL sideloading of "vivaldi_elf.dll"
references:
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023/08/03
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\vivaldi_elf.dll'
    filter_main_legit_path:
        Image|endswith: '\Vivaldi\Application\vivaldi.exe'
        ImageLoaded|contains: '\Vivaldi\Application\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```
