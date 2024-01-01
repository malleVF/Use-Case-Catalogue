---
title: "Github Outside Collaborator Detected"
status: "test"
created: "2023/01/20"
last_modified: ""
tags: [persistence, collection, t1098_001, t1098_003, t1213_003, detection_rule]
logsrc_product: "github"
logsrc_service: "audit"
level: "medium"
---

## Github Outside Collaborator Detected

### Description

Detects when an organization member or an outside collaborator is added to or removed from a project board or has their permission level changed or when an owner removes an outside collaborator from an organization or when two-factor authentication is required in an organization and an outside collaborator does not use 2FA or disables 2FA.


```yml
title: Github Outside Collaborator Detected
id: eaa9ac35-1730-441f-9587-25767bde99d7
status: test
description: |
    Detects when an organization member or an outside collaborator is added to or removed from a project board or has their permission level changed or when an owner removes an outside collaborator from an organization or when two-factor authentication is required in an organization and an outside collaborator does not use 2FA or disables 2FA.
author: Muhammad Faisal
date: 2023/01/20
references:
    - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions
    - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization
tags:
    - attack.persistence
    - attack.collection
    - attack.t1098.001
    - attack.t1098.003
    - attack.t1213.003
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'project.update_user_permission'
            - 'org.remove_outside_collaborator'
    condition: selection
fields:
    - 'action'
    - 'actor'
    - 'org'
    - 'actor_location.country_code'
falsepositives:
    - Validate the actor if permitted to access the repo.
    - Validate the Multifactor Authentication changes.
level: medium

```
