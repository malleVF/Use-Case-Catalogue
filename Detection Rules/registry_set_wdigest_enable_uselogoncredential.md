---
title: "Wdigest Enable UseLogonCredential"
status: "test"
created: "2019/09/12"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Wdigest Enable UseLogonCredential

### Description

Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials

```yml
title: Wdigest Enable UseLogonCredential
id: d6a9b252-c666-4de6-8806-5561bbbd3bdc
status: test
description: Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials
references:
    - https://threathunterplaybook.com/hunts/windows/190510-RegModWDigestDowngrade/notebook.html
    - https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649
    - https://github.com/redcanaryco/atomic-red-team/blob/73fcfa1d4863f6a4e17f90e54401de6e30a312bb/atomics/T1112/T1112.md#atomic-test-3---modify-registry-to-store-logon-credentials
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2019/09/12
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: 'WDigest\UseLogonCredential'
        Details: DWORD (0x00000001)
    condition: selection
falsepositives:
    - Unknown
level: high

```