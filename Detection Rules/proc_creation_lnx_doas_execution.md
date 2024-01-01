---
title: "Linux Doas Tool Execution"
status: "stable"
created: "2022/01/20"
last_modified: ""
tags: [privilege_escalation, t1548, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Linux Doas Tool Execution

### Description

Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.

```yml
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
references:
    - https://research.splunk.com/endpoint/linux_doas_tool_execution/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022/01/20
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
falsepositives:
    - Unlikely
level: low

```
