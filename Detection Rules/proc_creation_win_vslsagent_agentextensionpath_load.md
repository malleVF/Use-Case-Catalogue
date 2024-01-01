---
title: "Suspicious Vsls-Agent Command With AgentExtensionPath Load"
status: "test"
created: "2022/10/30"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Vsls-Agent Command With AgentExtensionPath Load

### Description

Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter

```yml
title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
id: 43103702-5886-11ed-9b6a-0242ac120002
status: test
description: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
references:
    - https://twitter.com/bohops/status/1583916360404729857
author: bohops
date: 2022/10/30
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vsls-agent.exe'
        CommandLine|contains: '--agentExtensionPath'
    filter:
        CommandLine|contains: 'Microsoft.VisualStudio.LiveShare.Agent.'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives depend on custom use of vsls-agent.exe
level: medium

```