---
title: "Uncommon Extension Shim Database Installation Via Sdbinst.EXE"
status: "test"
created: "2023/08/01"
last_modified: "2023/12/13"
tags: [persistence, privilege_escalation, t1546_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Uncommon Extension Shim Database Installation Via Sdbinst.EXE

### Description

Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims


```yml
title: Uncommon Extension Shim Database Installation Via Sdbinst.EXE
id: 18ee686c-38a3-4f65-9f44-48a077141f42
related:
    - id: 517490a7-115a-48c6-8862-1a481504d5a8
      type: derived
status: test
description: |
    Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
    Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/01
modified: 2023/12/13
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\sdbinst.exe'
        - OriginalFileName: 'sdbinst.exe'
    filter_main_legit_ext:
        CommandLine|contains: '.sdb'
    filter_main_svchost:
        # ParentImage|endswith: ':\Windows\System32\svchost.exe'
        - CommandLine|endswith: ' -mm'
        - CommandLine|contains: ' -m -bg'
    filter_main_null:
        CommandLine: null
    filter_main_empty:
        CommandLine: ''
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```
