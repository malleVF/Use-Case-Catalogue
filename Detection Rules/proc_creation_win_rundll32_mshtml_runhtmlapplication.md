---
title: "Mshtml DLL RunHTMLApplication Abuse"
status: "test"
created: "2022/08/14"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Mshtml DLL RunHTMLApplication Abuse

### Description

Detects suspicious command line using the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, htpp...)

```yml
title: Mshtml DLL RunHTMLApplication Abuse
id: 4782eb5a-a513-4523-a0ac-f3082b26ac5c
related:
    - id: 9f06447a-a33a-4cbe-a94f-a3f43184a7a3
      type: derived
status: test
description: Detects suspicious command line using the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, htpp...)
references:
    - https://twitter.com/n1nj4sec/status/1421190238081277959
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/14
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\..\'
            - 'mshtml'
            - 'RunHTMLApplication'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
