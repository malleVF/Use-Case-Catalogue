---
title: "TeamViewer Remote Session"
status: "test"
created: "2022/01/30"
last_modified: ""
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## TeamViewer Remote Session

### Description

Detects the creation of log files during a TeamViewer remote session

```yml
title: TeamViewer Remote Session
id: 162ab1e4-6874-4564-853c-53ec3ab8be01
status: test
description: Detects the creation of log files during a TeamViewer remote session
references:
    - https://www.teamviewer.com/en-us/
author: Florian Roth (Nextron Systems)
date: 2022/01/30
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection1:
        TargetFilename|endswith:
            - '\TeamViewer\RemotePrinting\tvprint.db'
            - '\TeamViewer\TVNetwork.log'
    selection2:
        TargetFilename|contains|all:
            - '\TeamViewer'
            - '_Logfile.log'
    condition: 1 of selection*
falsepositives:
    - Legitimate uses of TeamViewer in an organisation
level: medium

```