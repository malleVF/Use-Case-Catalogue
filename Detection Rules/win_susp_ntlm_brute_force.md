---
title: "NTLM Brute Force"
status: "test"
created: "2022/02/02"
last_modified: ""
tags: [credential_access, t1110, detection_rule]
logsrc_product: "windows"
logsrc_service: "ntlm"
level: "medium"
---

## NTLM Brute Force

### Description

Detects common NTLM brute force device names

```yml
title: NTLM Brute Force
id: 9c8acf1a-cbf9-4db6-b63c-74baabe03e59
status: test
description: Detects common NTLM brute force device names
references:
    - https://www.varonis.com/blog/investigate-ntlm-brute-force
author: Jerry Shockley '@jsh0x'
date: 2022/02/02
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8004
    devicename:
        WorkstationName:
            - 'Rdesktop'
            - 'Remmina'
            - 'Freerdp'
            - 'Windows7'
            - 'Windows8'
            - 'Windows2012'
            - 'Windows2016'
            - 'Windows2019'
    condition: selection and devicename
falsepositives:
    - Systems with names equal to the spoofed ones used by the brute force tools
level: medium

```
