---
title: "Potential Libvlc.DLL Sideloading"
status: "experimental"
created: "2023/04/17"
last_modified: ""
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Libvlc.DLL Sideloading

### Description

Detects potential DLL sideloading of "libvlc.dll", a DLL that is legitimately used by "VLC.exe"

```yml
title: Potential Libvlc.DLL Sideloading
id: bf9808c4-d24f-44a2-8398-b65227d406b6
status: experimental
description: Detects potential DLL sideloading of "libvlc.dll", a DLL that is legitimately used by "VLC.exe"
references:
    - https://www.trendmicro.com/en_us/research/23/c/earth-preta-updated-stealthy-strategies.html
    - https://hijacklibs.net/entries/3rd_party/vlc/libvlc.html
author: X__Junior
date: 2023/04/17
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\libvlc.dll'
    filter_main_vlc:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\VideoLAN\VLC\'
            - 'C:\Program Files\VideoLAN\VLC\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - False positives are expected if VLC is installed in non-default locations
level: medium

```