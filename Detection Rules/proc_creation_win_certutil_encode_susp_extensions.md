---
title: "Suspicious File Encoded To Base64 Via Certutil.EXE"
status: "experimental"
created: "2023/05/15"
last_modified: ""
tags: [defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious File Encoded To Base64 Via Certutil.EXE

### Description

Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious

```yml
title: Suspicious File Encoded To Base64 Via Certutil.EXE
id: ea0cdc3e-2239-4f26-a947-4e8f8224e464
related:
    - id: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
      type: derived
status: experimental
description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious
references:
    - https://www.virustotal.com/gui/file/35c22725a92d5cb1016b09421c0a6cdbfd860fd4778b3313669b057d4a131cb7/behavior
    - https://www.virustotal.com/gui/file/427616528b7dbc4a6057ac89eb174a3a90f7abcf3f34e5a359b7a910d82f7a72/behavior
    - https://www.virustotal.com/gui/file/34de4c8beded481a4084a1fd77855c3e977e8ac643e5c5842d0f15f7f9b9086f/behavior
    - https://www.virustotal.com/gui/file/4abe1395a09fda06d897a9c4eb247278c1b6cddda5d126ce5b3f4f499e3b8fa2/behavior
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/15
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains:
            - '-encode'
            - '/encode'
    selection_extension:
        CommandLine|contains:
            - '.acl'
            - '.bat'
            - '.doc'
            - '.gif'
            - '.jpeg'
            - '.jpg'
            - '.mp3'
            - '.pdf'
            - '.png'
            - '.ppt'
            - '.tmp'
            - '.xls'
            - '.xml'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```