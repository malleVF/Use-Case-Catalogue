---
title: "PowerShell Script With File Upload Capabilities"
status: "experimental"
created: "2022/01/07"
last_modified: "2023/05/04"
tags: [exfiltration, t1020, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## PowerShell Script With File Upload Capabilities

### Description

Detects PowerShell scripts leveraging the "Invoke-WebRequest" cmdlet to send data via either "PUT" or "POST" method.

```yml
title: PowerShell Script With File Upload Capabilities
id: d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb
status: experimental
description: Detects PowerShell scripts leveraging the "Invoke-WebRequest" cmdlet to send data via either "PUT" or "POST" method.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1020/T1020.md
    - https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2
author: frack113
date: 2022/01/07
modified: 2023/05/04
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    product: windows
    category: ps_script
    definition: bade5735-5ab0-4aa7-a642-a11be0e40872
detection:
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
    selection_flag:
        ScriptBlockText|contains:
            - '-Method Put'
            - '-Method Post'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low

```