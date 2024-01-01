---
title: "Format.com FileSystem LOLBIN"
status: "test"
created: "2022/01/04"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Format.com FileSystem LOLBIN

### Description

Detects the execution of format.com with a suspicious filesystem selection that could indicate a defense evasion activity in which format.com is used to load malicious DLL files or other programs

```yml
title: Format.com FileSystem LOLBIN
id: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
status: test
description: Detects the execution of format.com with a suspicious filesystem selection that could indicate a defense evasion activity in which format.com is used to load malicious DLL files or other programs
references:
    - https://twitter.com/0gtweet/status/1477925112561209344
    - https://twitter.com/wdormann/status/1478011052130459653?s=20
author: Florian Roth (Nextron Systems)
date: 2022/01/04
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\format.com'
        CommandLine|contains: '/fs:'
    filter:
        CommandLine|contains:
            - '/fs:FAT'
            - '/fs:exFAT'
            - '/fs:NTFS'
            - '/fs:UDF'
            - '/fs:ReFS'
    condition: selection and not 1 of filter*
falsepositives:
    - Unknown
level: high

```