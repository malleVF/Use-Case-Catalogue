---
title: "Disable Microsoft Defender Firewall via Registry"
status: "test"
created: "2022/01/09"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Microsoft Defender Firewall via Registry

### Description

Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage

```yml
title: Disable Microsoft Defender Firewall via Registry
id: 974515da-6cc5-4c95-ae65-f97f9150ec7f
status: test
description: Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md#atomic-test-2---disable-microsoft-defender-firewall-via-registry
author: frack113
date: 2022/01/09
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall
        # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall
        # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall
        TargetObject|startswith: 'HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\'
        TargetObject|endswith: '\EnableFirewall'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
