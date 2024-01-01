---
title: "EventLog EVTX File Deleted"
status: "experimental"
created: "2023/02/15"
last_modified: ""
tags: [defense_evasion, t1070, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## EventLog EVTX File Deleted

### Description

Detects the deletion of the event log files which may indicate an attempt to destroy forensic evidence

```yml
title: EventLog EVTX File Deleted
id: 63c779ba-f638-40a0-a593-ddd45e8b1ddc
status: experimental
description: Detects the deletion of the event log files which may indicate an attempt to destroy forensic evidence
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\System32\winevt\Logs\'
        TargetFilename|endswith: '.evtx'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
