---
title: "Google Workspace Role Modified or Deleted"
status: "test"
created: "2021/08/24"
last_modified: "2023/10/11"
tags: [impact, detection_rule]
logsrc_product: "gcp"
logsrc_service: "google_workspace.admin"
level: "medium"
---

## Google Workspace Role Modified or Deleted

### Description

Detects when an a role is modified or deleted in Google Workspace.

```yml
title: Google Workspace Role Modified or Deleted
id: 6aef64e3-60c6-4782-8db3-8448759c714e
status: test
description: Detects when an a role is modified or deleted in Google Workspace.
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings
author: Austin Songer
date: 2021/08/24
modified: 2023/10/11
tags:
    - attack.impact
logsource:
    product: gcp
    service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName:
            - DELETE_ROLE
            - RENAME_ROLE
            - UPDATE_ROLE
    condition: selection
falsepositives:
    - Unknown

level: medium

```
