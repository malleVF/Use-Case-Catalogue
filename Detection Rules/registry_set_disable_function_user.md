---
title: "Disable Internal Tools or Feature in Registry"
status: "experimental"
created: "2022/03/18"
last_modified: "2023/11/20"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Internal Tools or Feature in Registry

### Description

Detects registry modifications that change features of internal Windows tools (malware like Agent Tesla uses this technique)

```yml
title: Disable Internal Tools or Feature in Registry
id: e2482f8d-3443-4237-b906-cc145d87a076
status: experimental
description: Detects registry modifications that change features of internal Windows tools (malware like Agent Tesla uses this technique)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md
    - https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://www.malwarebytes.com/blog/detections/pum-optional-nodispbackgroundpage
    - https://www.malwarebytes.com/blog/detections/pum-optional-nodispcpl
author: frack113, Nasreddine Bencherchali (Nextron Systems), CrimpSec
date: 2022/03/18
modified: 2023/11/20
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection_set_1:
        TargetObject|endswith:
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\StartMenuLogOff'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableChangePassword'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskmgr'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoDispBackgroundPage'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoDispCPL'
            - 'SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableNotificationCenter'
            - 'SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD'
        Details: 'DWORD (0x00000001)'
    selection_set_0:
        TargetObject|endswith:
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon'
            - 'SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled'
            - 'SYSTEM\CurrentControlSet\Control\Storage\Write Protection'
            - 'SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect'
        Details: 'DWORD (0x00000000)'
    condition: 1 of selection_set_*
falsepositives:
    - Legitimate admin script
level: medium

```