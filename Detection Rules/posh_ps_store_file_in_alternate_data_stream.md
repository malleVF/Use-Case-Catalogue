---
title: "Powershell Store File In Alternate Data Stream"
status: "test"
created: "2021/09/02"
last_modified: "2022/12/25"
tags: [defense_evasion, t1564_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Powershell Store File In Alternate Data Stream

### Description

Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.

```yml
title: Powershell Store File In Alternate Data Stream
id: a699b30e-d010-46c8-bbd1-ee2e26765fe9
status: test
description: Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
author: frack113
date: 2021/09/02
modified: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_compspec:
        ScriptBlockText|contains|all:
            - 'Start-Process'
            - '-FilePath "$env:comspec" '
            - '-ArgumentList '
            - '>'
    condition: selection_compspec
falsepositives:
    - Unknown
level: medium

```