---
title: "Tap Driver Installation"
status: "test"
created: "2019/10/24"
last_modified: "2022/12/25"
tags: [exfiltration, t1048, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Tap Driver Installation

### Description

Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques

```yml
title: Tap Driver Installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
status: test
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
modified: 2022/12/25
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains: 'tap0901'
    condition: selection
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium

```
