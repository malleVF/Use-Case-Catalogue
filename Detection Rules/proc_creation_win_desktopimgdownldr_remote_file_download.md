---
title: "Remote File Download Via Desktopimgdownldr Utility"
status: "test"
created: "2022/09/27"
last_modified: ""
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote File Download Via Desktopimgdownldr Utility

### Description

Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.

```yml
title: Remote File Download Via Desktopimgdownldr Utility
id: 214641c2-c579-4ecb-8427-0cf19df6842e
status: test
description: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
references:
    - https://www.elastic.co/guide/en/security/current/remote-file-download-via-desktopimgdownldr-utility.html
author: Tim Rauch
date: 2022/09/27
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\desktopimgdownldr.exe'
        ParentImage|endswith: '\desktopimgdownldr.exe'
        CommandLine|contains: '/lockscreenurl:http'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
