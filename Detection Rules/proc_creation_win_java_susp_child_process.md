---
title: "Suspicious Processes Spawned by Java.EXE"
status: "experimental"
created: "2021/12/17"
last_modified: "2023/11/09"
tags: [initial_access, persistence, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Processes Spawned by Java.EXE

### Description

Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j)

```yml
title: Suspicious Processes Spawned by Java.EXE
id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
related:
    - id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
      type: similar
status: experimental
description: Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j)
author: Andreas Hunkeler (@Karneades), Florian Roth
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
            - '\AppVLP.exe'
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\certutil.exe'
            - '\cscript.exe'
            - '\curl.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\mftrace.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\query.exe'
            - '\reg.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\scriptrunner.exe'
            - '\sh.exe'
            - '\systeminfo.exe'
            - '\whoami.exe'
            - '\wmic.exe'        # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: high

```
