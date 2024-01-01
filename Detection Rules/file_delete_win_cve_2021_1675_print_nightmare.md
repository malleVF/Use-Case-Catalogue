---
title: "Potential PrintNightmare Exploitation Attempt"
status: "experimental"
created: "2021/07/01"
last_modified: "2023/02/17"
tags: [persistence, defense_evasion, privilege_escalation, t1574, cve_2021_1675, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential PrintNightmare Exploitation Attempt

### Description

Detect DLL deletions from Spooler Service driver folder. This might be a potential exploitation attempt of CVE-2021-1675

```yml
title: Potential PrintNightmare Exploitation Attempt
id: 5b2bbc47-dead-4ef7-8908-0cf73fcbecbf
status: experimental
description: Detect DLL deletions from Spooler Service driver folder. This might be a potential exploitation attempt of CVE-2021-1675
references:
    - https://github.com/hhlxf/PrintNightmare
    - https://github.com/cube0x0/CVE-2021-1675
author: Bhabesh Raj
date: 2021/07/01
modified: 2023/02/17
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574
    - cve.2021.1675
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        Image|endswith: '\spoolsv.exe'
        TargetFilename|contains: 'C:\Windows\System32\spool\drivers\x64\3\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
