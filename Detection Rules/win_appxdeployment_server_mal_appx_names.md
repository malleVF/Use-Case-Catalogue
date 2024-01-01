---
title: "Potential Malicious AppX Package Installation Attempts"
status: "test"
created: "2023/01/11"
last_modified: "2023/01/12"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: "appxdeployment-server"
level: "medium"
---

## Potential Malicious AppX Package Installation Attempts

### Description

Detects potential installation or installation attempts of known malicious appx packages

```yml
title: Potential Malicious AppX Package Installation Attempts
id: 09d3b48b-be17-47f5-bf4e-94e7e75d09ce
status: test
description: Detects potential installation or installation attempts of known malicious appx packages
references:
    - https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
    - https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
    - https://forensicitguy.github.io/analyzing-magnitude-magniber-appx/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/11
modified: 2023/01/12
tags:
    - attack.defense_evasion
logsource:
    product: windows
    service: appxdeployment-server
detection:
    selection:
        EventID:
            - 400
            - 401
        # Add more malicious package names
        # TODO: Investigate the packages here https://github.com/sophoslabs/IoCs/blob/master/Troj-BazarBackdoor.csv based on this report https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
        PackageFullName|contains: '3669e262-ec02-4e9d-bcb4-3d008b4afac9'
    condition: selection
falsepositives:
    - Rare occasions where a malicious package uses the exact same name and version as a legtimate application
level: medium

```