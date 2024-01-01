---
title: "Failed DNS Zone Transfer"
status: "experimental"
created: "2023/05/24"
last_modified: ""
tags: [reconnaissance, t1590_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "dns-server"
level: "medium"
---

## Failed DNS Zone Transfer

### Description

Detects when a DNS zone transfer failed.

```yml
title: Failed DNS Zone Transfer
id: 6d444368-6da1-43fe-b2fc-44202430480e
status: experimental
description: Detects when a DNS zone transfer failed.
references:
    - https://kb.eventtracker.com/evtpass/evtpages/EventId_6004_Microsoft-Windows-DNS-Server-Service_65410.asp
author: Zach Mathis
date: 2023/05/24
tags:
    - attack.reconnaissance
    - attack.t1590.002
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID: 6004 # The DNS server received a zone transfer request from %1 for a non-existent or non-authoritative zone %2.
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
