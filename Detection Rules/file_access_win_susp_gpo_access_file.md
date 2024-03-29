---
title: "Access To Potentially Sensitive Sysvol Files By Uncommon Application"
status: "experimental"
created: "2023/12/21"
last_modified: ""
tags: [credential_access, t1552_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Access To Potentially Sensitive Sysvol Files By Uncommon Application

### Description

Detects file access requests to potentially sensitive files hosted on the Windows Sysvol share.

```yml
title: Access To Potentially Sensitive Sysvol Files By Uncommon Application
id: d51694fe-484a-46ac-92d6-969e76d60d10
related:
    - id: 8344c19f-a023-45ff-ad63-a01c5396aea0
      type: derived
status: experimental
description: Detects file access requests to potentially sensitive files hosted on the Windows Sysvol share.
references:
    - https://github.com/vletoux/pingcastle
author: frack113
date: 2023/12/21
tags:
    - attack.credential_access
    - attack.t1552.006
logsource:
    category: file_access
    product: windows
    definition: 'Requirements: Microsoft-Windows-Kernel-File ETW provider'
detection:
    selection:
        FileName|startswith: '\\'
        FileName|contains|all:
            - '\sysvol\'
            - '\Policies\'
        FileName|endswith:
            - 'audit.csv'
            - 'Files.xml'
            - 'GptTmpl.inf'
            - 'groups.xml'
            - 'Registry.pol'
            - 'Registry.xml'
            - 'scheduledtasks.xml'
            - 'scripts.ini'
            - 'services.xml'
    filter_main_generic:
        Image|startswith:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\explorer.exe'
            - ':\Windows\system32\'
            - ':\Windows\SysWOW64\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```
