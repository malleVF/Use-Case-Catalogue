---
title: "Powershell Defender Disable Scan Feature"
status: "test"
created: "2022/03/03"
last_modified: "2022/03/07"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Powershell Defender Disable Scan Feature

### Description

Detects requests to disable Microsoft Defender features using PowerShell commands

```yml
title: Powershell Defender Disable Scan Feature
id: 1ec65a5f-9473-4f12-97da-622044d6df21
status: test
description: Detects requests to disable Microsoft Defender features using PowerShell commands
references:
    - https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
    - https://www.virustotal.com/gui/file/d609799091731d83d75ec5d1f030571af20c45efeeb94840b67ea09a3283ab65/behavior/C2AE
    - https://www.virustotal.com/gui/search/content%253A%2522Set-MpPreference%2520-Disable%2522/files
author: Florian Roth (Nextron Systems)
date: 2022/03/03
modified: 2022/03/07
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'Add-MpPreference '
            - 'Set-MpPreference '
    selection2:
        CommandLine|contains:
            - 'DisableRealtimeMonitoring '
            - 'DisableIOAVProtection '
            - 'DisableBehaviorMonitoring '
            - 'DisableBlockAtFirstSeen '
    selection3:
        CommandLine|contains:
            - '$true'
            - ' 1 '
    encoded_command:
        CommandLine|base64offset|contains:
            - 'DisableRealtimeMonitoring '
            - 'DisableIOAVProtection '
            - 'DisableBehaviorMonitoring '
            - 'DisableBlockAtFirstSeen '
            - 'disablerealtimemonitoring '
            - 'disableioavprotection '
            - 'disablebehaviormonitoring '
            - 'disableblockatfirstseen '
        CommandLine|contains:
            - 'RABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAUgBlAGEAbAB0AGkAbQBlAE0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'EAGkAcwBhAGIAbABlAFIAZQBhAGwAdABpAG0AZQBNAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'RABpAHMAYQBiAGwAZQBJAE8AQQBWAFAAcgBvAHQAZQBjAHQAaQBvAG4AIA'
            - 'QAaQBzAGEAYgBsAGUASQBPAEEAVgBQAHIAbwB0AGUAYwB0AGkAbwBuACAA'
            - 'EAGkAcwBhAGIAbABlAEkATwBBAFYAUAByAG8AdABlAGMAdABpAG8AbgAgA'
            - 'RABpAHMAYQBiAGwAZQBCAGUAaABhAHYAaQBvAHIATQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAQgBlAGgAYQB2AGkAbwByAE0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'EAGkAcwBhAGIAbABlAEIAZQBoAGEAdgBpAG8AcgBNAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'RABpAHMAYQBiAGwAZQBCAGwAbwBjAGsAQQB0AEYAaQByAHMAdABTAGUAZQBuACAA'
            - 'QAaQBzAGEAYgBsAGUAQgBsAG8AYwBrAEEAdABGAGkAcgBzAHQAUwBlAGUAbgAgA'
            - 'EAGkAcwBhAGIAbABlAEIAbABvAGMAawBBAHQARgBpAHIAcwB0AFMAZQBlAG4AIA'
            - 'ZABpAHMAYQBiAGwAZQByAGUAYQBsAHQAaQBtAGUAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAcgBlAGEAbAB0AGkAbQBlAG0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'kAGkAcwBhAGIAbABlAHIAZQBhAGwAdABpAG0AZQBtAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'ZABpAHMAYQBiAGwAZQBpAG8AYQB2AHAAcgBvAHQAZQBjAHQAaQBvAG4AIA'
            - 'QAaQBzAGEAYgBsAGUAaQBvAGEAdgBwAHIAbwB0AGUAYwB0AGkAbwBuACAA'
            - 'kAGkAcwBhAGIAbABlAGkAbwBhAHYAcAByAG8AdABlAGMAdABpAG8AbgAgA'
            - 'ZABpAHMAYQBiAGwAZQBiAGUAaABhAHYAaQBvAHIAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAYgBlAGgAYQB2AGkAbwByAG0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'kAGkAcwBhAGIAbABlAGIAZQBoAGEAdgBpAG8AcgBtAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'ZABpAHMAYQBiAGwAZQBiAGwAbwBjAGsAYQB0AGYAaQByAHMAdABzAGUAZQBuACAA'
            - 'QAaQBzAGEAYgBsAGUAYgBsAG8AYwBrAGEAdABmAGkAcgBzAHQAcwBlAGUAbgAgA'
            - 'kAGkAcwBhAGIAbABlAGIAbABvAGMAawBhAHQAZgBpAHIAcwB0AHMAZQBlAG4AIA'
    condition: all of selection* or encoded_command
falsepositives:
    - Possible Admin Activity
    - Other Cmdlets that may use the same parameters
level: high

```
