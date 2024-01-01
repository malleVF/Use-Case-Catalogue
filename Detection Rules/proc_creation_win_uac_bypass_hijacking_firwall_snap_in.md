---
title: "UAC Bypass via Windows Firewall Snap-In Hijack"
status: "test"
created: "2022/09/27"
last_modified: ""
tags: [privilege_escalation, t1548, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## UAC Bypass via Windows Firewall Snap-In Hijack

### Description

Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in

```yml
title: UAC Bypass via Windows Firewall Snap-In Hijack
id: e52cb31c-10ed-4aea-bcb7-593c9f4a315b
status: test
description: Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in
references:
    - https://www.elastic.co/guide/en/security/current/uac-bypass-via-windows-firewall-snap-in-hijack.html#uac-bypass-via-windows-firewall-snap-in-hijack
author: Tim Rauch
date: 2022/09/27
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mmc.exe'
        ParentCommandLine|contains: 'WF.msc'
    filter:
        Image|endswith: '\WerFault.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```