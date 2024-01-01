---
title: "Access To Browser Credential Files By Uncommon Application"
status: "experimental"
created: "2022/04/09"
last_modified: "2023/12/18"
tags: [t1003, credential_access, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Access To Browser Credential Files By Uncommon Application

### Description

Detects file access requests to browser credential stores by uncommon processes.
Could indicate potential attempt of credential stealing.
Requires heavy baselining before usage


```yml
title: Access To Browser Credential Files By Uncommon Application
id: 91cb43db-302a-47e3-b3c8-7ede481e27bf
status: experimental
description: |
    Detects file access requests to browser credential stores by uncommon processes.
    Could indicate potential attempt of credential stealing.
    Requires heavy baselining before usage
references:
    - https://www.zscaler.com/blogs/security-research/ffdroider-stealer-targeting-social-media-platform-users
    - https://github.com/lclevy/firepwd
author: frack113
date: 2022/04/09
modified: 2023/12/18
tags:
    - attack.t1003
    - attack.credential_access
logsource:
    category: file_access
    product: windows
    definition: 'Requirements: Microsoft-Windows-Kernel-File ETW provider'
detection:
    selection_ie:
        FileName|endswith: '\Appdata\Local\Microsoft\Windows\WebCache\WebCacheV01.dat'
    selection_firefox:
        FileName|endswith:
            - '\cookies.sqlite'
            - 'release\key3.db'  # Firefox
            - 'release\key4.db'  # Firefox
            - 'release\logins.json' # Firefox
    selection_chromium:
        FileName|contains:
            - '\Appdata\Local\Chrome\User Data\Default\Login Data'
            - '\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies'
            - '\AppData\Local\Google\Chrome\User Data\Local State'
    filter_main_system:
        Image: System
    filter_main_generic:
        # This filter is added to avoid large amount of FP with 3rd party software. You should remove this in favour of specific filter per-application
        Image|contains:
            - ':\Program Files\'
            - ':\Program Files (x86)\'
            - ':\WINDOWS\system32\'
            - ':\WINDOWS\SysWOW64\'
    filter_optional_defender:
        Image|contains: ':\ProgramData\Microsoft\Windows Defender\'
        Image|endswith:
            - '\MpCopyAccelerator.exe'
            - '\MsMpEng.exe'
    filter_optional_thor:
        Image|endswith:
            - '\thor64.exe'
            - '\thor.exe'
    condition: 1 of selection_* and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Antivirus, Anti-Spyware, Anti-Malware Software
    - Backup software
    - Legitimate software installed on partitions other than "C:\"
    - Searching software such as "everything.exe"
level: medium

```