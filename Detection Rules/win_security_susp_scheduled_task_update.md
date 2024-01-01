---
title: "Suspicious Scheduled Task Update"
status: "test"
created: "2022/12/05"
last_modified: ""
tags: [execution, privilege_escalation, persistence, t1053_005, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Suspicious Scheduled Task Update

### Description

Detects update to a scheduled task event that contain suspicious keywords.

```yml
title: Suspicious Scheduled Task Update
id: 614cf376-6651-47c4-9dcc-6b9527f749f4
related:
    - id: 1c0e41cd-21bb-4433-9acc-4a2cd6367b9b # ProcCreation schtasks change
      type: similar
status: test
description: Detects update to a scheduled task event that contain suspicious keywords.
references:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/05
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection. We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection_eid:
        EventID: 4702
    selection_paths:
        TaskContentNew|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\WINDOWS\Temp\'
            - 'C:\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Temporary Internet'
            - 'C:\ProgramData\'
            - 'C:\Perflogs\'
    selection_commands:
        TaskContentNew|contains:
            - 'regsvr32'
            - 'rundll32'
            - 'cmd.exe</Command>'
            - 'cmd</Command>'
            - '<Arguments>/c '
            - '<Arguments>/k '
            - '<Arguments>/r '
            - 'powershell'
            - 'pwsh'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'certutil'
            - 'bitsadmin'
            - 'bash.exe'
            - 'bash '
            - 'scrcons'
            - 'wmic '
            - 'wmic.exe'
            - 'forfiles'
            - 'scriptrunner'
            - 'hh.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```