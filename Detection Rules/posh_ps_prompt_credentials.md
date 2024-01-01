---
title: "PowerShell Credential Prompt"
status: "test"
created: "2017/04/09"
last_modified: "2022/12/25"
tags: [credential_access, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Credential Prompt

### Description

Detects PowerShell calling a credential prompt

```yml
title: PowerShell Credential Prompt
id: ca8b77a9-d499-4095-b793-5d5f330d450e
status: test
description: Detects PowerShell calling a credential prompt
references:
    - https://twitter.com/JohnLaTwC/status/850381440629981184
    - https://t.co/ezOTGy1a1G
author: John Lambert (idea), Florian Roth (Nextron Systems)
date: 2017/04/09
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'PromptForCredential'
    condition: selection
falsepositives:
    - Unknown
level: high

```
