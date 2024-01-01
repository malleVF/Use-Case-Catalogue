---
title: "Disable Macro Runtime Scan Scope"
status: "experimental"
created: "2022/10/25"
last_modified: "2023/08/17"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable Macro Runtime Scan Scope

### Description

Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros

```yml
title: Disable Macro Runtime Scan Scope
id: ab871450-37dc-4a3a-997f-6662aa8ae0f1
description: Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros
status: experimental
date: 2022/10/25
modified: 2023/08/17
author: Nasreddine Bencherchali (Nextron Systems)
references:
    - https://www.microsoft.com/en-us/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/
    - https://admx.help/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_MacroRuntimeScanScope
    - https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/28cc6a2802d8176195ac19b3c8e9a749009a82a3/src/AMSIbypasses.vba
tags:
    - attack.defense_evasion
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains|all:
            - '\SOFTWARE\'
            - '\Microsoft\Office\'
            - '\Common\Security'
        TargetObject|endswith: '\MacroRuntimeScanScope'
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: high

```
