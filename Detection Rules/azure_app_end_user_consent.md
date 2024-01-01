---
title: "End User Consent"
status: "test"
created: "2022/07/28"
last_modified: ""
tags: [credential_access, t1528, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "low"
---

## End User Consent

### Description

Detects when an end user consents to an application

```yml
title: End User Consent
id: 9b2cc4c4-2ad4-416d-8e8e-ee6aa6f5035a
status: test
description: Detects when an end user consents to an application
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#end-user-consent
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022/07/28
tags:
    - attack.credential_access
    - attack.t1528
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        ConsentContext.IsAdminConsent: 'false'
    condition: selection
falsepositives:
    - Unknown
level: low

```
