---
title: "Suspicious Shells Spawn by Java Utility Keytool"
status: "test"
created: "2021/12/22"
last_modified: "2023/01/21"
tags: [initial_access, persistence, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Shells Spawn by Java Utility Keytool

### Description

Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)

```yml
title: Suspicious Shells Spawn by Java Utility Keytool
id: 90fb5e62-ca1f-4e22-b42e-cc521874c938
status: test
description: Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)
references:
    - https://redcanary.com/blog/intelligence-insights-december-2021
    - https://www.synacktiv.com/en/publications/how-to-exploit-cve-2021-40539-on-manageengine-adselfservice-plus.html
author: Andreas Hunkeler (@Karneades)
date: 2021/12/22
modified: 2023/01/21
tags:
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\keytool.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\scrcons.exe'
            - '\regsvr32.exe'
            - '\hh.exe'
            - '\wmic.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
            - '\mftrace.exe'
            - '\AppVLP.exe'
            - '\systeminfo.exe'
            - '\reg.exe'
            - '\query.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```