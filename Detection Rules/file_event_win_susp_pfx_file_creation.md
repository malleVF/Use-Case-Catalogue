---
title: "Suspicious PFX File Creation"
status: "test"
created: "2020/05/02"
last_modified: "2022/07/07"
tags: [credential_access, t1552_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious PFX File Creation

### Description

A general detection for processes creating PFX files. This could be an indicator of an adversary exporting a local certificate to a PFX file.

```yml
title: Suspicious PFX File Creation
id: dca1b3e8-e043-4ec8-85d7-867f334b5724
status: test
description: A general detection for processes creating PFX files. This could be an indicator of an adversary exporting a local certificate to a PFX file.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/14
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/6.B.1_6392C9F1-D975-4F75-8A70-433DEDD7F622.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/05/02
modified: 2022/07/07
tags:
    - attack.credential_access
    - attack.t1552.004
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.pfx'
    filter:
        TargetFilename|contains|all:
            - '\Templates\Windows\Windows_TemporaryKey.pfx'
            - '\CMake\'
    condition: selection and not 1 of filter*
falsepositives:
    - System administrators managing certififcates.
level: medium

```
