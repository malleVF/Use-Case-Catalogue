---
title: "Potential Cookies Session Hijacking"
status: "experimental"
created: "2023/07/27"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Cookies Session Hijacking

### Description

Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.

```yml
title: Potential Cookies Session Hijacking
id: 5a6e1e16-07de-48d8-8aae-faa766c05e88
status: experimental
description: Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.
references:
    - https://curl.se/docs/manpage.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/07/27
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\curl.exe'
        - OriginalFileName: 'curl.exe'
    selection_cli:
        - CommandLine|re: '\s-c\s'
        - CommandLine|contains: '--cookie-jar'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
