---
title: "GatherNetworkInfo.VBS Reconnaissance Script Output"
status: "experimental"
created: "2023/02/08"
last_modified: ""
tags: [discovery, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## GatherNetworkInfo.VBS Reconnaissance Script Output

### Description

Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".

```yml
title: GatherNetworkInfo.VBS Reconnaissance Script Output
id: f92a6f1e-a512-4a15-9735-da09e78d7273
related:
    - id: 575dce0c-8139-4e30-9295-1ee75969f7fe # ProcCreation LOLBIN
      type: similar
    - id: 07aa184a-870d-413d-893a-157f317f6f58 # ProcCreation Susp
      type: similar
status: experimental
description: Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".
references:
    - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
    - https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/08
tags:
    - attack.discovery
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\System32\config'
        TargetFilename|endswith:
            - '\Hotfixinfo.txt'
            - '\netiostate.txt'
            - '\sysportslog.txt'
            - '\VmSwitchLog.evtx'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
