---
title: "OSACompile Run-Only Execution"
status: "test"
created: "2023/01/31"
last_modified: ""
tags: [t1059_002, execution, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "high"
---

## OSACompile Run-Only Execution

### Description

Detects potential suspicious run-only executions compiled using OSACompile

```yml
title: OSACompile Run-Only Execution
id: b9d9b652-d8ed-4697-89a2-a1186ee680ac
status: test
description: Detects potential suspicious run-only executions compiled using OSACompile
references:
    - https://redcanary.com/blog/applescript/
    - https://ss64.com/osx/osacompile.html
author: Sohan G (D4rkCiph3r)
date: 2023/01/31
tags:
    - attack.t1059.002
    - attack.execution
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'osacompile'
            - ' -x '
            - ' -e '
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unknown
level: high

```
