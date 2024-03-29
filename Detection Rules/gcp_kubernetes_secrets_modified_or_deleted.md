---
title: "Google Cloud Kubernetes Secrets Modified or Deleted"
status: "test"
created: "2021/08/09"
last_modified: "2022/10/09"
tags: [credential_access, detection_rule]
logsrc_product: "gcp"
logsrc_service: "gcp.audit"
level: "medium"
---

## Google Cloud Kubernetes Secrets Modified or Deleted

### Description

Identifies when the Secrets are Modified or Deleted.

```yml
title: Google Cloud Kubernetes Secrets Modified or Deleted
id: 2f0bae2d-bf20-4465-be86-1311addebaa3
status: test
description: Identifies when the Secrets are Modified or Deleted.
references:
    - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
author: Austin Songer @austinsonger
date: 2021/08/09
modified: 2022/10/09
tags:
    - attack.credential_access
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name:
            - io.k8s.core.v*.secrets.create
            - io.k8s.core.v*.secrets.update
            - io.k8s.core.v*.secrets.patch
            - io.k8s.core.v*.secrets.delete
    condition: selection
falsepositives:
    - Secrets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
