---
title: "DLL Sideloading by VMware Xfer Utility"
status: "test"
created: "2022/08/02"
last_modified: ""
tags: [defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DLL Sideloading by VMware Xfer Utility

### Description

Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL

```yml
title: DLL Sideloading by VMware Xfer Utility
id: ebea773c-a8f1-42ad-a856-00cb221966e8
status: test
description: Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
references:
    - https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/02
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\VMwareXferlogs.exe'
    filter: # VMware might be installed in another path so update the rule accordingly
        Image|startswith: 'C:\Program Files\VMware\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high

```
