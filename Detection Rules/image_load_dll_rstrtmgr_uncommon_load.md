---
title: "Load Of RstrtMgr.DLL By An Uncommon Process"
status: "experimental"
created: "2023/11/28"
last_modified: ""
tags: [impact, defense_evasion, t1486, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Load Of RstrtMgr.DLL By An Uncommon Process

### Description

Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process.
This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
It could also be used for anti-analysis purposes by shut downing specific processes.


```yml
title: Load Of RstrtMgr.DLL By An Uncommon Process
id: 3669afd2-9891-4534-a626-e5cf03810a61
related:
    - id: b48492dc-c5ef-4572-8dff-32bc241c15c8
      type: derived
status: experimental
description: |
    Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process.
    This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
    It could also be used for anti-analysis purposes by shut downing specific processes.
references:
    - https://www.crowdstrike.com/blog/windows-restart-manager-part-1/
    - https://www.crowdstrike.com/blog/windows-restart-manager-part-2/
    - https://www.swascan.com/cactus-ransomware-malware-analysis/
    - https://taiwan.postsen.com/business/88601/Hamas-hackers-use-data-destruction-software-BiBi-which-consumes-a-lot-of-processor-resources-to-wipe-Windows-computer-data--iThome.html
author: Luc Génaux
date: 2023/11/28
tags:
    - attack.impact
    - attack.defense_evasion
    - attack.t1486
    - attack.t1562.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        - ImageLoaded|endswith: '\RstrtMgr.dll'
        - OriginalFileName: 'RstrtMgr.dll'
    filter_main_generic:
        Image|contains:
            - ':\$WINDOWS.~BT\'
            - ':\$WinREAgent\'
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\ProgramData\'
            - ':\Windows\explorer.exe'
            - ':\Windows\SoftwareDistribution\'
            - ':\Windows\SysNative\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
            - ':\WUDownloadCache\'
    filter_main_user_software_installations:
        Image|contains|all:
            - ':\Users\'
            - '\AppData\Local\Temp\is-'
            - '.tmp\'
        Image|endswith: '.tmp'
    filter_main_admin_software_installations:
        Image|contains: ':\Windows\Temp\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Other legitimate Windows processes not currently listed
    - Processes related to software installation
level: low

```