---
title: "Security Support Provider (SSP) Added to LSA Configuration"
status: "test"
created: "2019/01/18"
last_modified: "2022/08/09"
tags: [persistence, t1547_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Security Support Provider (SSP) Added to LSA Configuration

### Description

Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.

```yml
title: Security Support Provider (SSP) Added to LSA Configuration
id: eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc
status: test
description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.
references:
    - https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
author: iwillkeepwatch
date: 2019/01/18
modified: 2022/08/09
tags:
    - attack.persistence
    - attack.t1547.005
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        TargetObject:
            - 'HKLM\System\CurrentControlSet\Control\Lsa\Security Packages'
            - 'HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages'
    exclusion_images:
        Image:
            - 'C:\Windows\system32\msiexec.exe'
            - 'C:\Windows\syswow64\MsiExec.exe'
    condition: selection_registry and not exclusion_images
falsepositives:
    - Unlikely
level: critical

```
