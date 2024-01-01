---
title: "New DLL Added to AppCertDlls Registry Key"
status: "test"
created: "2019/10/25"
last_modified: "2021/11/27"
tags: [persistence, t1546_009, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New DLL Added to AppCertDlls Registry Key

### Description

Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.


```yml
title: New DLL Added to AppCertDlls Registry Key
id: 6aa1d992-5925-4e9f-a49b-845e51d1de01
status: test
description: |
  Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
  by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.
references:
    - http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
    - https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.t1546.009
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        - TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
        # key rename
        - NewName: 'HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unknown
level: medium

```