---
title: "Registry Persistence via Service in Safe Mode"
status: "experimental"
created: "2022/04/04"
last_modified: "2023/10/27"
tags: [defense_evasion, t1564_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Registry Persistence via Service in Safe Mode

### Description

Detects the modification of the registry to allow a driver or service to persist in Safe Mode.

```yml
title: Registry Persistence via Service in Safe Mode
id: 1547e27c-3974-43e2-a7d7-7f484fb928ec
status: experimental
description: Detects the modification of the registry to allow a driver or service to persist in Safe Mode.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-33---windows-add-registry-value-to-load-service-in-safe-mode-without-network
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-34---windows-add-registry-value-to-load-service-in-safe-mode-with-network
author: frack113
date: 2022/04/04
modified: 2023/10/27
tags:
    - attack.defense_evasion
    - attack.t1564.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith:
            - 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\'
            - 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\'
        TargetObject|endswith: '\(Default)'
        Details: Service
    filter_sophos:
        Image: 'C:\WINDOWS\system32\msiexec.exe'
        TargetObject:
            - 'HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal\SAVService\(Default)'
            - 'HKLM\System\CurrentControlSet\Control\SafeBoot\Network\SAVService\(Default)'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
