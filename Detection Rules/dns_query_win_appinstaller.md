---
title: "AppX Package Installation Attempts Via AppInstaller.EXE"
status: "test"
created: "2021/11/24"
last_modified: "2023/11/09"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## AppX Package Installation Attempts Via AppInstaller.EXE

### Description

Detects DNS queries made by "AppInstaller.EXE". The AppInstaller is the default handler for the "ms-appinstaller" URI. It attempts to load/install a package from the referenced URL


```yml
title: AppX Package Installation Attempts Via AppInstaller.EXE
id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
related:
    - id: 180c7c5c-d64b-4a63-86e9-68910451bc8b
      type: derived
status: test
description: |
    Detects DNS queries made by "AppInstaller.EXE". The AppInstaller is the default handler for the "ms-appinstaller" URI. It attempts to load/install a package from the referenced URL
references:
    - https://twitter.com/notwhickey/status/1333900137232523264
    - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
author: frack113
date: 2021/11/24
modified: 2023/11/09
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        Image|startswith: 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_'
        Image|endswith: '\AppInstaller.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```