---
title: "Suspicious Rundll32 Execution With Image Extension"
status: "experimental"
created: "2023/03/13"
last_modified: ""
tags: [defense_evasion, t1218_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Rundll32 Execution With Image Extension

### Description

Detects the execution of Rundll32.exe with DLL files masquerading as image files

```yml
title: Suspicious Rundll32 Execution With Image Extension
id: 4aa6040b-3f28-44e3-a769-9208e5feb5ec
related:
    - id: 089fc3d2-71e8-4763-a8a5-c97fbb0a403e
      type: similar
status: experimental
description: Detects the execution of Rundll32.exe with DLL files masquerading as image files
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Hieu Tran
date: 2023/03/13
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.exe'
    selection_cli:
        CommandLine|contains:
            - '.bmp'
            - '.cr2'
            - '.eps'
            - '.gif'
            - '.ico'
            - '.jpeg'
            - '.jpg'
            - '.nef'
            - '.orf'
            - '.png'
            - '.raw'
            - '.sr2'
            - '.tif'
            - '.tiff'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
