---
title: "Shell Process Spawned by Java.EXE"
status: "test"
created: "2021/12/17"
last_modified: "2023/11/09"
tags: [initial_access, persistence, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Shell Process Spawned by Java.EXE

### Description

Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)

```yml
title: Shell Process Spawned by Java.EXE
id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
related:
    - id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
      type: similar
status: test
description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
date: 2021/12/17
modified: 2023/11/09
tags:
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\java.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_build:
        ParentImage|contains: 'build'  # excluding CI build agents
        CommandLine|contains: 'build'  # excluding CI build agents
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: medium

```
