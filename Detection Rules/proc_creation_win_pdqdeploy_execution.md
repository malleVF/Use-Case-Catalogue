---
title: "PDQ Deploy Remote Adminstartion Tool Execution"
status: "test"
created: "2022/10/01"
last_modified: "2023/01/30"
tags: [execution, lateral_movement, t1072, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PDQ Deploy Remote Adminstartion Tool Execution

### Description

Detect use of PDQ Deploy remote admin tool

```yml
title: PDQ Deploy Remote Adminstartion Tool Execution
id: d679950c-abb7-43a6-80fb-2a480c4fc450
related:
    - id: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
      type: similar
status: test
description: Detect use of PDQ Deploy remote admin tool
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1072/T1072.md
    - https://www.pdq.com/pdq-deploy/
author: frack113
date: 2022/10/01
modified: 2023/01/30
tags:
    - attack.execution
    - attack.lateral_movement
    - attack.t1072
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: PDQ Deploy Console
        - Product: PDQ Deploy
        - Company: PDQ.com
        - OriginalFileName: PDQDeployConsole.exe
    condition: selection
falsepositives:
    - Legitimate use
level: medium

```