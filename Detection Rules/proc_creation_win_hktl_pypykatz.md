---
title: "HackTool - Pypykatz Credentials Dumping Activity"
status: "test"
created: "2022/01/05"
last_modified: "2023/02/05"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Pypykatz Credentials Dumping Activity

### Description

Detects the usage of "pypykatz" to obtain stored credentials. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database through Windows registry where the SAM database is stored

```yml
title: HackTool - Pypykatz Credentials Dumping Activity
id: a29808fd-ef50-49ff-9c7a-59a9b040b404
status: test
description: Detects the usage of "pypykatz" to obtain stored credentials. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database through Windows registry where the SAM database is stored
references:
    - https://github.com/skelsec/pypykatz
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-2---registry-parse-with-pypykatz
author: frack113
date: 2022/01/05
modified: 2023/02/05
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - \pypykatz.exe
            - \python.exe
        CommandLine|contains|all:
            - 'live'
            - 'registry'
    condition: selection
falsepositives:
    - Unknown
level: high

```