---
title: "HackTool - SharpEvtMute DLL Load"
status: "experimental"
created: "2022/09/07"
last_modified: "2023/02/17"
tags: [defense_evasion, t1562_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - SharpEvtMute DLL Load

### Description

Detects the load of EvtMuteHook.dll, a key component of SharpEvtHook, a tool that tampers with the Windows event logs

```yml
title: HackTool - SharpEvtMute DLL Load
id: 49329257-089d-46e6-af37-4afce4290685
related:
    - id: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c # Process Creation
      type: similar
status: experimental
description: Detects the load of EvtMuteHook.dll, a key component of SharpEvtHook, a tool that tampers with the Windows event logs
references:
    - https://github.com/bats3c/EvtMute
author: Florian Roth (Nextron Systems)
date: 2022/09/07
modified: 2023/02/17
tags:
    - attack.defense_evasion
    - attack.t1562.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        - Hashes|contains: 'IMPHASH=330768A4F172E10ACB6287B87289D83B'
        - Imphash: '330768a4f172e10acb6287b87289d83b'
    condition: selection
falsepositives:
    - Other DLLs with the same Imphash
level: high

```
