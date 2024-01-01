---
title: "Adwind RAT / JRAT File Artifact"
status: "test"
created: "2017/11/10"
last_modified: "2022/12/02"
tags: [execution, t1059_005, t1059_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Adwind RAT / JRAT File Artifact

### Description

Detects javaw.exe in AppData folder as used by Adwind / JRAT

```yml
title: Adwind RAT / JRAT File Artifact
id: 0bcfabcb-7929-47f4-93d6-b33fb67d34d1
related:
    - id: 1fac1481-2dbc-48b2-9096-753c49b4ec71
      type: derived
status: test
description: Detects javaw.exe in AppData folder as used by Adwind / JRAT
references:
    - https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
    - https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf
author: Florian Roth (Nextron Systems), Tom Ueltschi, Jonhnathan Ribeiro, oscd.community
date: 2017/11/10
modified: 2022/12/02
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: file_event
    product: windows
detection:
    selection:
        - TargetFilename|contains|all:
              - '\AppData\Roaming\Oracle\bin\java'
              - '.exe'
        - TargetFilename|contains|all:
              - '\Retrive'
              - '.vbs'
    condition: selection
level: high

```