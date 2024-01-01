---
title: "End User Consent Blocked"
status: "test"
created: "2022/07/10"
last_modified: ""
tags: [credential_access, t1528, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## End User Consent Blocked

### Description

Detects when end user consent is blocked due to risk-based consent.

```yml
title: End User Consent Blocked
id: 7091372f-623c-4293-bc37-20c32b3492be
status: test
description: Detects when end user consent is blocked due to risk-based consent.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#end-user-stopped-due-to-risk-based-consent
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022/07/10
tags:
    - attack.credential_access
    - attack.t1528
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        failure_status_reason: 'Microsoft.online.Security.userConsentBlockedForRiskyAppsExceptions'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
