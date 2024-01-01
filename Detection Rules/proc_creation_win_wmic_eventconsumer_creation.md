---
title: "New ActiveScriptEventConsumer Created Via Wmic.EXE"
status: "test"
created: "2021/06/25"
last_modified: "2023/02/14"
tags: [persistence, t1546_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## New ActiveScriptEventConsumer Created Via Wmic.EXE

### Description

Detects WMIC executions in which an event consumer gets created. This could be used to establish persistence

```yml
title: New ActiveScriptEventConsumer Created Via Wmic.EXE
id: ebef4391-1a81-4761-a40a-1db446c0e625
status: test
description: Detects WMIC executions in which an event consumer gets created. This could be used to establish persistence
references:
    - https://twitter.com/johnlatwc/status/1408062131321270282?s=12
    - https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
author: Florian Roth (Nextron Systems)
date: 2021/06/25
modified: 2023/02/14
tags:
    - attack.persistence
    - attack.t1546.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'ActiveScriptEventConsumer'
            - ' CREATE '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate software creating script event consumers
level: high

```
