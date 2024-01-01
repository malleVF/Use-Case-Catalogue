---
title: "Atera Agent Installation"
status: "test"
created: "2021/09/01"
last_modified: "2022/12/25"
tags: [t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## Atera Agent Installation

### Description

Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators

```yml
title: Atera Agent Installation
id: 87261fb2-69d0-42fe-b9de-88c6b5f65a43
status: test
description: Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators
references:
    - https://www.advintel.io/post/secret-backdoor-behind-conti-ransomware-operation-introducing-atera-agent
author: Bhabesh Raj
date: 2021/09/01
modified: 2022/12/25
tags:
    - attack.t1219
logsource:
    service: application
    product: windows
detection:
    selection:
        EventID: 1033
        Provider_Name: MsiInstaller
        Message|contains: AteraAgent
    condition: selection
falsepositives:
    - Legitimate Atera agent installation
level: high

```
