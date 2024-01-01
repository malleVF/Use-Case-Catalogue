---
title: "Windows Shell/Scripting Application File Write to Suspicious Folder"
status: "experimental"
created: "2021/11/20"
last_modified: "2023/03/29"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Windows Shell/Scripting Application File Write to Suspicious Folder

### Description

Detects Windows shells and scripting applications that write files to suspicious folders

```yml
title: Windows Shell/Scripting Application File Write to Suspicious Folder
id: 1277f594-a7d1-4f28-a2d3-73af5cbeab43
status: experimental
description: Detects Windows shells and scripting applications that write files to suspicious folders
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2021/11/20
modified: 2023/03/29
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: file_event
    product: windows
detection:
    selection_1:
        Image|endswith:
            - '\bash.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\msbuild.exe'  # https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/defense_evasion_execution_msbuild_started_by_office_app.toml
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\sh.exe'
            - '\wscript.exe'
        TargetFilename|startswith:
            - 'C:\PerfLogs\'
            - 'C:\Users\Public\'
    selection_2:
        Image|endswith:
            - '\certutil.exe'
            - '\forfiles.exe'
            - '\mshta.exe'
            # - '\rundll32.exe' # Potential FP
            - '\schtasks.exe'
            - '\scriptrunner.exe'
            - '\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
        TargetFilename|contains:
            - 'C:\PerfLogs\'
            - 'C:\Users\Public\'
            - 'C:\Windows\Temp\'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```