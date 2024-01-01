---
title: "Enable Local Manifest Installation With Winget"
status: "experimental"
created: "2023/04/17"
last_modified: "2023/08/17"
tags: [defense_evasion, persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Enable Local Manifest Installation With Winget

### Description

Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.

```yml
title: Enable Local Manifest Installation With Winget
id: fa277e82-9b78-42dd-b05c-05555c7b6015
status: experimental
description: Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.
references:
    - https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/04/17
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.persistence
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: '\AppInstaller\EnableLocalManifestFiles'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Administrators or developers might enable this for testing purposes or to install custom private packages
level: medium

```
