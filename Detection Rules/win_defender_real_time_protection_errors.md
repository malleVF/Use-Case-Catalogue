---
title: "Windows Defender Real-Time Protection Failure/Restart"
status: "stable"
created: "2023/03/28"
last_modified: "2023/05/05"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "windefend"
level: "medium"
---

## Windows Defender Real-Time Protection Failure/Restart

### Description

Detects issues with Windows Defender Real-Time Protection features

```yml
title: Windows Defender Real-Time Protection Failure/Restart
id: dd80db93-6ec2-4f4c-a017-ad40da6ffe81
status: stable
description: Detects issues with Windows Defender Real-Time Protection features
references:
    - Internal Research
    - https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
    - https://gist.github.com/nasbench/33732d6705cbdc712fae356f07666346 # Contains the list of Feature Names (use for filtering purposes)
author: Nasreddine Bencherchali (Nextron Systems), Christopher Peacock '@securepeacock' (Update)
date: 2023/03/28
modified: 2023/05/05
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 3002 # Real-Time Protection feature has encountered an error and failed
            - 3007 # Real-time Protection feature has restarted
    filter_optional_network_inspection:
        Feature_Name: '%%886' # Network Inspection System
        Reason:
            - '%%892' # The system is missing updates that are required for running Network Inspection System.  Install the required updates and restart the device.
            - '%%858' # Antimalware security intelligence has stopped functioning for an unknown reason. In some instances, restarting the service may resolve the problem.
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Some crashes can occur sometimes and the event doesn't provide enough information to tune out these cases. Manual exception is required
level: medium

```