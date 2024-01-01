---
title: "Detected Windows Software Discovery"
status: "test"
created: "2020/10/16"
last_modified: "2022/10/09"
tags: [discovery, t1518, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Detected Windows Software Discovery

### Description

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.

```yml
title: Detected Windows Software Discovery
id: e13f668e-7f95-443d-98d2-1816a7648a7b
related:
    - id: 2650dd1a-eb2a-412d-ac36-83f06c4f2282
      type: derived
status: test
description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
    - https://github.com/harleyQu1nn/AggressorScripts # AVQuery.cna
author: Nikita Nazarov, oscd.community
date: 2020/10/16
modified: 2022/10/09
tags:
    - attack.discovery
    - attack.t1518
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'    # Example: reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
        CommandLine|contains|all:
            - 'query'
            - '\software\'
            - '/v'
            - 'svcversion'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```