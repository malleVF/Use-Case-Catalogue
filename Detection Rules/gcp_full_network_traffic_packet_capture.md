---
title: "Google Full Network Traffic Packet Capture"
status: "test"
created: "2021/08/13"
last_modified: "2022/10/09"
tags: [collection, t1074, detection_rule]
logsrc_product: "gcp"
logsrc_service: "gcp.audit"
level: "medium"
---

## Google Full Network Traffic Packet Capture

### Description

Identifies potential full network packet capture in gcp. This feature can potentially be abused to read sensitive data from unencrypted internal traffic.

```yml
title: Google Full Network Traffic Packet Capture
id: 980a7598-1e7f-4962-9372-2d754c930d0e
status: test
description: Identifies potential full network packet capture in gcp. This feature can potentially be abused to read sensitive data from unencrypted internal traffic.
references:
    - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
    - https://developers.google.com/resources/api-libraries/documentation/compute/v1/java/latest/com/google/api/services/compute/Compute.PacketMirrorings.html
author: Austin Songer @austinsonger
date: 2021/08/13
modified: 2022/10/09
tags:
    - attack.collection
    - attack.t1074
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name:
            - v*.Compute.PacketMirrorings.Get
            - v*.Compute.PacketMirrorings.Delete
            - v*.Compute.PacketMirrorings.Insert
            - v*.Compute.PacketMirrorings.Patch
            - v*.Compute.PacketMirrorings.List
            - v*.Compute.PacketMirrorings.aggregatedList
    condition: selection
falsepositives:
    - Full Network Packet Capture may be done by a system or network administrator.
    - If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
