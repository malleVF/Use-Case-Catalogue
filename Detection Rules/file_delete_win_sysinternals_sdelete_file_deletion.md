---
title: "File Deleted Via Sysinternals SDelete"
status: "test"
created: "2020/05/02"
last_modified: "2023/02/15"
tags: [defense_evasion, t1070_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## File Deleted Via Sysinternals SDelete

### Description

Detects the deletion of files by the Sysinternals SDelete utility. It looks for the common name pattern used to rename files.

```yml
title: File Deleted Via Sysinternals SDelete
id: 6ddab845-b1b8-49c2-bbf7-1a11967f64bc
status: test
description: Detects the deletion of files by the Sysinternals SDelete utility. It looks for the common name pattern used to rename files.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/9
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/4.B.4_83D62033-105A-4A02-8B75-DAB52D8D51EC.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/05/02
modified: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|endswith:
            - '.AAA'
            - '.ZZZ'
    filter_wireshark:
        TargetFilename|endswith: '\Wireshark\radius\dictionary.alcatel-lucent.aaa'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitime usage of SDelete
level: medium

```