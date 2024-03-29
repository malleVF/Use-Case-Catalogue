---
title: "New Github Organization Member Added"
status: "test"
created: "2023/01/29"
last_modified: ""
tags: [persistence, t1136_003, detection_rule]
logsrc_product: "github"
logsrc_service: "audit"
level: "informational"
---

## New Github Organization Member Added

### Description

Detects when a new member is added or invited to a github organization.

```yml
title: New Github Organization Member Added
id: 3908d64a-3c06-4091-b503-b3a94424533b
status: test
description: Detects when a new member is added or invited to a github organization.
author: Muhammad Faisal
date: 2023/01/29
references:
    - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#dependabot_alerts-category-actions
tags:
    - attack.persistence
    - attack.t1136.003
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'org.add_member'
            - 'org.invite_member'
    condition: selection
fields:
    - 'action'
    - 'actor'
    - 'org'
    - 'actor_location.country_code'
    - 'transport_protocol_name'
    - 'repository'
    - 'repo'
    - 'repository_public'
    - '@timestamp'
falsepositives:
    - Organization approved new members
level: informational

```
