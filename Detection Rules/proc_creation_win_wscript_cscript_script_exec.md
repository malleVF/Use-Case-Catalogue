---
title: "WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript"
status: "test"
created: "2019/01/16"
last_modified: "2023/05/15"
tags: [execution, t1059_005, t1059_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript

### Description

Detects script file execution (.js, .jse, .vba, .vbe, .vbs, .wsf) by Wscript/Cscript

```yml
title: WSF/JSE/JS/VBA/VBE File Execution Via Cscript/Wscript
id: 1e33157c-53b1-41ad-bbcc-780b80b58288
related:
    - id: 23250293-eed5-4c39-b57a-841c8933a57d
      type: obsoletes
status: test
description: Detects script file execution (.js, .jse, .vba, .vbe, .vbs, .wsf) by Wscript/Cscript
author: Michael Haag
date: 2019/01/16
modified: 2023/05/15
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName:
              - 'wscript.exe'
              - 'cscript.exe'
        - Image|endswith:
              - '\wscript.exe'
              - '\cscript.exe'
    selection_cli:
        CommandLine|contains:
            - '.js'
            - '.jse'
            - '.vba'
            - '.vbe'
            - '.vbs'
            - '.wsf'
    condition: all of selection_*
falsepositives:
    - Some additional tuning is required. It is recommended to add the user profile path in CommandLine if it is getting too noisy.
level: medium

```
