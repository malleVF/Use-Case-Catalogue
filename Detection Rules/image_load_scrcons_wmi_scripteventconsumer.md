---
title: "WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load"
status: "test"
created: "2020/09/02"
last_modified: "2023/02/22"
tags: [lateral_movement, privilege_escalation, persistence, t1546_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load

### Description

Detects signs of the WMI script host process "scrcons.exe" loading scripting DLLs which could indicates WMI ActiveScriptEventConsumers EventConsumers activity.

```yml
title: WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load
id: b439f47d-ef52-4b29-9a2f-57d8a96cb6b8
status: test
description: Detects signs of the WMI script host process "scrcons.exe" loading scripting DLLs which could indicates WMI ActiveScriptEventConsumers EventConsumers activity.
references:
    - https://twitter.com/HunterPlaybook/status/1301207718355759107
    - https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
    - https://threathunterplaybook.com/hunts/windows/200902-RemoteWMIActiveScriptEventConsumers/notebook.html
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/09/02
modified: 2023/02/22
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.003
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\scrcons.exe'
        ImageLoaded|endswith:
            - '\vbscript.dll'
            - '\wbemdisp.dll'
            - '\wshom.ocx'
            - '\scrrun.dll'
    condition: selection
falsepositives:
    - Legitimate event consumers
    - Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button
level: medium

```