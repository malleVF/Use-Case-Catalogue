---
title: "Testing Usage of Uncommonly Used Port"
status: "test"
created: "2022/01/23"
last_modified: ""
tags: [command_and_control, t1571, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Testing Usage of Uncommonly Used Port

### Description

Adversaries may communicate using a protocol and port paring that are typically not associated.
For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443.


```yml
title: Testing Usage of Uncommonly Used Port
id: adf876b3-f1f8-4aa9-a4e4-a64106feec06
status: test
description: |
    Adversaries may communicate using a protocol and port paring that are typically not associated.
    For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1571/T1571.md#atomic-test-1---testing-usage-of-uncommonly-used-port-with-powershell
    - https://docs.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps
author: frack113
date: 2022/01/23
tags:
    - attack.command_and_control
    - attack.t1571
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - Test-NetConnection
            - '-ComputerName '
            - '-port '
    filter:
        ScriptBlockText|contains:
            - ' 443 '
            - ' 80 '
    condition: selection and not filter
falsepositives:
    - Legitimate administrative script
level: medium

```