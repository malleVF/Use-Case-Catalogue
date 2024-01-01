---
title: "Windows Defender Threat Detected"
status: "stable"
created: "2020/07/28"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: "windefend"
level: "high"
---

## Windows Defender Threat Detected

### Description

Detects actions taken by Windows Defender malware detection engines

```yml
title: Windows Defender Threat Detected
id: 57b649ef-ff42-4fb0-8bf6-62da243a1708
status: stable
description: Detects actions taken by Windows Defender malware detection engines
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
author: Ján Trenčanský
date: 2020/07/28
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 1006 # The antimalware engine found malware or other potentially unwanted software.
            - 1015 # The antimalware platform detected suspicious behavior.
            - 1116 # The antimalware platform detected malware or other potentially unwanted software.
            - 1117 # he antimalware platform performed an action to protect your system from malware or other potentially unwanted software.
    condition: selection
falsepositives:
    - Unlikely
level: high

```
