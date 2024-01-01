---
title: "Create Volume Shadow Copy with Powershell"
status: "test"
created: "2022/01/12"
last_modified: ""
tags: [credential_access, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Create Volume Shadow Copy with Powershell

### Description

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information

```yml
title: Create Volume Shadow Copy with Powershell
id: afd12fed-b0ec-45c9-a13d-aa86625dac81
status: test
description: Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information
references:
    - https://attack.mitre.org/datasources/DS0005/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1&viewFallbackFrom=powershell-7
author: frack113
date: 2022/01/12
tags:
    - attack.credential_access
    - attack.t1003.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - win32_shadowcopy
            - ').Create('
            - ClientAccessible
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: high

```
