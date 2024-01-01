---
title: "Google Cloud DNS Zone Modified or Deleted"
status: "test"
created: "2021/08/15"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "gcp"
logsrc_service: "gcp.audit"
level: "medium"
---

## Google Cloud DNS Zone Modified or Deleted

### Description

Identifies when a DNS Zone is modified or deleted in Google Cloud.

```yml
title: Google Cloud DNS Zone Modified or Deleted
id: 28268a8f-191f-4c17-85b2-f5aa4fa829c3
status: test
description: Identifies when a DNS Zone is modified or deleted in Google Cloud.
references:
    - https://cloud.google.com/dns/docs/reference/v1/managedZones
author: Austin Songer @austinsonger
date: 2021/08/15
modified: 2022/10/09
tags:
    - attack.impact
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name:
            - Dns.ManagedZones.Delete
            - Dns.ManagedZones.Update
            - Dns.ManagedZones.Patch
    condition: selection
falsepositives:
    - Unknown
level: medium

```
