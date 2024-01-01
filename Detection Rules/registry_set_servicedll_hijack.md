---
title: "ServiceDll Hijack"
status: "experimental"
created: "2022/02/04"
last_modified: "2023/08/17"
tags: [persistence, privilege_escalation, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## ServiceDll Hijack

### Description

Detects changes to the "ServiceDLL" value related to a service in the registry. This is often used as a method of persistence.

```yml
title: ServiceDll Hijack
id: 612e47e9-8a59-43a6-b404-f48683f45bd6
status: experimental
description: Detects changes to the "ServiceDLL" value related to a service in the registry. This is often used as a method of persistence.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md#atomic-test-4---tinyturla-backdoor-service-w64time
    - https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/
author: frack113
date: 2022/02/04
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKLM\System\CurrentControlSet\Services\'
        TargetObject|endswith: '\Parameters\ServiceDll'
    filter_printextensionmanger:
        Details: 'C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll'
    filter_domain_controller:
        Image: 'C:\Windows\system32\lsass.exe'
        TargetObject|endswith: '\CurrentControlSet\Services\NTDS\Parameters\ServiceDll'
        Details: '%%systemroot%%\system32\ntdsa.dll'
    filter_poqexec:
        Image: 'C:\Windows\System32\poqexec.exe'
    condition: selection and not 1 of filter*
falsepositives:
    - Administrative scripts
    - Installation of a service
level: medium

```