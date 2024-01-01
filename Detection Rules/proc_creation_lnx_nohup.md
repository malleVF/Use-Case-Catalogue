---
title: "Nohup Execution"
status: "test"
created: "2022/06/06"
last_modified: ""
tags: [execution, t1059_004, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Nohup Execution

### Description

Detects usage of nohup which could be leveraged by an attacker to keep a process running or break out from restricted environments

```yml
title: Nohup Execution
id: e4ffe466-6ff8-48d4-94bd-e32d1a6061e2
status: test
description: Detects usage of nohup which could be leveraged by an attacker to keep a process running or break out from restricted environments
references:
    - https://gtfobins.github.io/gtfobins/nohup/
    - https://en.wikipedia.org/wiki/Nohup
    - https://www.computerhope.com/unix/unohup.htm
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022/06/06
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/nohup'
    condition: selection
falsepositives:
    - Administrators or installed processes that leverage nohup
level: medium

```
