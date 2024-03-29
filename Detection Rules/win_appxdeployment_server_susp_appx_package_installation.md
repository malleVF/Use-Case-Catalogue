---
title: "Suspicious AppX Package Installation Attempt"
status: "test"
created: "2023/01/11"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: "appxdeployment-server"
level: "medium"
---

## Suspicious AppX Package Installation Attempt

### Description

Detects an appx package installation with the error code "0x80073cff" which indicates that the package didn't meet the signing requirements and could be suspicious

```yml
title: Suspicious AppX Package Installation Attempt
id: 898d5fc9-fbc3-43de-93ad-38e97237c344
status: test
description: Detects an appx package installation with the error code "0x80073cff" which indicates that the package didn't meet the signing requirements and could be suspicious
references:
    - Internal Research
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/11
tags:
    - attack.defense_evasion
logsource:
    product: windows
    service: appxdeployment-server
detection:
    selection:
        EventID: 401
        ErrorCode: '0x80073cff' # Check ref section to learn more about this error code
    condition: selection
falsepositives:
    - Legitimate AppX packages not signed by MS used part of an enterprise
level: medium

```
