---
title: "Tap Driver Installation - Security"
status: "test"
created: "2019/10/24"
last_modified: "2022/11/29"
tags: [exfiltration, t1048, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Tap Driver Installation - Security

### Description

Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques

```yml
title: Tap Driver Installation - Security
id: 9c8afa4d-0022-48f0-9456-3712466f9701
related:
    - id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
      type: derived
status: test
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
modified: 2022/11/29
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceFileName|contains: 'tap0901'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium

```
