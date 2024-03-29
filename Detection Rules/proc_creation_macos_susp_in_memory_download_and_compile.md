---
title: "Potential In-Memory Download And Compile Of Payloads"
status: "experimental"
created: "2023/08/22"
last_modified: ""
tags: [command_and_control, execution, t1059_007, t1105, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## Potential In-Memory Download And Compile Of Payloads

### Description

Detects potential in-memory downloading and compiling of applets using curl and osacompile as seen used by XCSSET malware

```yml
title: Potential In-Memory Download And Compile Of Payloads
id: 13db8d2e-7723-4c2c-93c1-a4d36994f7ef
status: experimental
description: Detects potential in-memory downloading and compiling of applets using curl and osacompile as seen used by XCSSET malware
references:
    - https://redcanary.com/blog/mac-application-bundles/
author: Sohan G (D4rkCiph3r), Red Canary (idea)
date: 2023/08/22
tags:
    - attack.command_and_control
    - attack.execution
    - attack.t1059.007
    - attack.t1105
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        CommandLine|contains|all:
            - 'osacompile'
            - 'curl'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
