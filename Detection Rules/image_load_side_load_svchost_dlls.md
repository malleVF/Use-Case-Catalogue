---
title: "Svchost DLL Search Order Hijack"
status: "test"
created: "2019/10/28"
last_modified: "2021/11/27"
tags: [persistence, defense_evasion, t1574_002, t1574_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Svchost DLL Search Order Hijack

### Description

Detects DLL sideloading of DLLs that are loaded by the SCM for some services (IKE, IKEEXT, SessionEnv) which do not exists on a typical modern system
IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default.
An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a remote machine.


```yml
title: Svchost DLL Search Order Hijack
id: 602a1f13-c640-4d73-b053-be9a2fa58b77
status: test
description: |
    Detects DLL sideloading of DLLs that are loaded by the SCM for some services (IKE, IKEEXT, SessionEnv) which do not exists on a typical modern system
    IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:\Windows\System32\ by default.
    An attacker can place their malicious logic within the PROCESS_ATTACH block of their library and restart the aforementioned services "svchost.exe -k netsvcs" to gain code execution on a remote machine.
references:
    - https://decoded.avast.io/martinchlumecky/png-steganography/
    - https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992
author: SBousseaden
date: 2019/10/28
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        ImageLoaded|endswith:
            - '\tsmsisrv.dll'
            - '\tsvipsrv.dll'
            - '\wlbsctrl.dll'
    filter:
        ImageLoaded|startswith: 'C:\Windows\WinSxS\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
