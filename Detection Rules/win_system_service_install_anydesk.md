---
title: "Anydesk Remote Access Software Service Installation"
status: "test"
created: "2022/08/11"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Anydesk Remote Access Software Service Installation

### Description

Detects the installation of the anydesk software service. Which could be an indication of anydesk abuse if you the software isn't already used.

```yml
title: Anydesk Remote Access Software Service Installation
id: 530a6faa-ff3d-4022-b315-50828e77eef5
status: test
description: Detects the installation of the anydesk software service. Which could be an indication of anydesk abuse if you the software isn't already used.
references:
    - https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/11
tags:
    - attack.persistence
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName: 'AnyDesk Service'
    condition: selection
falsepositives:
    - Legitimate usage of the anydesk tool
level: medium

```
