---
title: "DCOM InternetExplorer.Application Iertutil DLL Hijack - Security"
status: "test"
created: "2020/10/12"
last_modified: "2022/11/26"
tags: [lateral_movement, t1021_002, t1021_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## DCOM InternetExplorer.Application Iertutil DLL Hijack - Security

### Description

Detects a threat actor creating a file named `iertutil.dll` in the `C:\Program Files\Internet Explorer\` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.

```yml
title: DCOM InternetExplorer.Application Iertutil DLL Hijack - Security
id: c39f0c81-7348-4965-ab27-2fde35a1b641
status: test
description: Detects a threat actor creating a file named `iertutil.dll` in the `C:\Program Files\Internet Explorer\` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
date: 2020/10/12
modified: 2022/11/26
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1021.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|endswith: '\Internet Explorer\iertutil.dll'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```