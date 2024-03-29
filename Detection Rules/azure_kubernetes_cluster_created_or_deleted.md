---
title: "Azure Kubernetes Cluster Created or Deleted"
status: "test"
created: "2021/08/07"
last_modified: "2022/08/23"
tags: [impact, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "low"
---

## Azure Kubernetes Cluster Created or Deleted

### Description

Detects when a Azure Kubernetes Cluster is created or deleted.

```yml
title: Azure Kubernetes Cluster Created or Deleted
id: 9541f321-7cba-4b43-80fc-fbd1fb922808
status: test
description: Detects when a Azure Kubernetes Cluster is created or deleted.
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
    - https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
    - https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
    - https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1
    - https://attack.mitre.org/matrices/enterprise/cloud/
author: Austin Songer @austinsonger
date: 2021/08/07
modified: 2022/08/23
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/WRITE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/DELETE
    condition: selection
falsepositives:
    - Kubernetes cluster being created or  deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Kubernetes cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low

```
