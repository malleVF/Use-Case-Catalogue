---
title: "Remote Thread Creation By Uncommon Source Image"
status: "experimental"
created: "2019/10/27"
last_modified: "2023/11/11"
tags: [privilege_escalation, defense_evasion, t1055, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Thread Creation By Uncommon Source Image

### Description

Detects uncommon processes creating remote threads

```yml
title: Remote Thread Creation By Uncommon Source Image
id: 66d31e5f-52d6-40a4-9615-002d3789a119
status: experimental
description: Detects uncommon processes creating remote threads
references:
    - Personal research, statistical analysis
    - https://lolbas-project.github.io
author: Perez Diego (@darkquassar), oscd.community
date: 2019/10/27
modified: 2023/11/11
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1055
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith:
            - '\bash.exe'
            - '\cscript.exe'
            - '\cvtres.exe'
            - '\defrag.exe'
            - '\dnx.exe'
            - '\esentutl.exe'
            - '\excel.exe'
            - '\expand.exe'
            - '\explorer.exe'
            - '\find.exe'
            - '\findstr.exe'
            - '\forfiles.exe'
            # - '\git.exe'
            - '\gpupdate.exe'
            - '\hh.exe'
            - '\iexplore.exe'
            - '\installutil.exe'
            - '\lync.exe'
            - '\makecab.exe'
            - '\mDNSResponder.exe'
            - '\monitoringhost.exe' # Loads .NET CLR by default and thus a favorite for process injection for .NET in-memory offensive tools.
            - '\msbuild.exe'
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\mspaint.exe'
            - '\outlook.exe'
            - '\ping.exe'
            - '\powerpnt.exe'
            - '\provtool.exe'
            - '\python.exe'
            - '\regsvr32.exe'
            - '\robocopy.exe'
            - '\runonce.exe'
            - '\sapcimc.exe'
            - '\schtasks.exe'
            - '\smartscreen.exe'
            - '\spoolsv.exe'
            # - '\taskhost.exe'  # disabled due to false positives
            - '\tstheme.exe'
            - '\userinit.exe'
            - '\vssadmin.exe'
            - '\vssvc.exe'
            - '\w3wp.exe'
            - '\winlogon.exe'
            - '\winscp.exe'
            - '\winword.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    filter_main_winlogon_1:
        SourceImage|endswith: ':\Windows\System32\winlogon.exe'
        TargetImage|endswith:
            - ':\Windows\System32\services.exe' # happens on Windows 7
            - ':\Windows\System32\wininit.exe' # happens on Windows 7
            - ':\Windows\System32\csrss.exe' # multiple OS
            - ':\Windows\System32\LogonUI.exe' # multiple OS
    filter_main_winlogon_2:
        SourceImage: 'C:\Windows\System32\winlogon.exe'
        TargetParentProcessId: 4
    filter_main_schtasks_conhost:
        SourceImage|endswith:
            - ':\Windows\System32\schtasks.exe'
            - ':\Windows\SysWOW64\schtasks.exe'
        TargetImage|endswith: ':\Windows\System32\conhost.exe'
    filter_main_explorer:
        SourceImage|endswith: ':\Windows\explorer.exe'
        TargetImage|endswith:
            - ':\Program Files (x86)\'
            - ':\Program Files\'
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
    filter_main_system:
        TargetImage: 'System'
    filter_main_msiexec:
        # Note: MSI installers will trigger this
        SourceImage|endswith: '\msiexec.exe'
        TargetImage|contains:
            - '\AppData\Local\'
            - ':\Program Files (x86)\'
            - ':\Program Files\'
    filter_optional_powerpnt:
        # Raised by the following issue: https://github.com/SigmaHQ/sigma/issues/2479
        SourceImage|contains: '\Microsoft Office\'
        SourceImage|endswith: '\POWERPNT.EXE'
        TargetImage|endswith: ':\Windows\System32\csrss.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high

```
