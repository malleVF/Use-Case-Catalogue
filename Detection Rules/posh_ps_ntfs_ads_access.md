---
title: "NTFS Alternate Data Stream"
status: "test"
created: "2018/07/24"
last_modified: "2022/12/25"
tags: [defense_evasion, t1564_004, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## NTFS Alternate Data Stream

### Description

Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.

```yml
title: NTFS Alternate Data Stream
id: 8c521530-5169-495d-a199-0a3a881ad24e
status: test
description: Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.
references:
    - http://www.powertheshell.com/ntfsstreams/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
author: Sami Ruohonen
date: 2018/07/24
modified: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.t1564.004
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_content:
        ScriptBlockText|contains:
            - set-content
            - add-content
    selection_stream:
        ScriptBlockText|contains: '-stream'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
