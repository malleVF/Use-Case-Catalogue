---
title: "Fake Instance Of Hxtsr.exe"
status: "test"
created: "2020/04/17"
last_modified: "2023/02/21"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Fake Instance Of Hxtsr.exe

### Description

HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.
HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files".
Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe".
Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe


```yml
title: Fake Instance Of Hxtsr.exe
id: 4e762605-34a8-406d-b72e-c1a089313320
status: test
description: |
    HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.
    HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files".
    Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe".
    Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe
author: Sreeman
date: 2020/04/17
modified: 2023/02/21
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: hxtsr.exe
    filter:
        CurrentDirectory|startswith: 'C:\program files\windowsapps\microsoft.windowscommunicationsapps_'
        CurrentDirectory|endswith: '\hxtsr.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```
