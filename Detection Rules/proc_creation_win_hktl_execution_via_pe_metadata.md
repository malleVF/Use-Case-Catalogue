---
title: "Suspicious Hacktool Execution - PE Metadata"
status: "test"
created: "2022/04/27"
last_modified: "2023/02/04"
tags: [credential_access, t1588_002, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Hacktool Execution - PE Metadata

### Description

Detects the execution of different Windows based hacktools via PE metadata (company, product, etc.) even if the files have been renamed

```yml
title: Suspicious Hacktool Execution - PE Metadata
id: 37c1333a-a0db-48be-b64b-7393b2386e3b
status: test
description: Detects the execution of different Windows based hacktools via PE metadata (company, product, etc.) even if the files have been renamed
references:
    - https://github.com/cube0x0
    - https://www.virustotal.com/gui/search/metadata%253ACube0x0/files
author: Florian Roth (Nextron Systems)
date: 2022/04/27
modified: 2023/02/04
tags:
    - attack.credential_access
    - attack.t1588.002
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Company: 'Cube0x0' # Detects the use of tools created by a well-known hacktool producer named "Cube0x0", which includes his handle in all binaries as company information in the PE headers (SharpPrintNightmare, KrbRelay, SharpMapExec, etc.)
    condition: selection
falsepositives:
    - Unlikely
level: high

```
