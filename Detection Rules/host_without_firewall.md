---
title: "Host Without Firewall"
status: "stable"
created: "2019/03/19"
last_modified: "2022/10/05"
tags: [, detection_rule]
logsrc_product: "qualys"
logsrc_service: ""
level: "low"
---

## Host Without Firewall

### Description

Host Without Firewall. Alert means not complied. Sigma for Qualys vulnerability scanner. Scan type - Vulnerability Management.

```yml
title: Host Without Firewall
id: 6b2066c8-3dc7-4db7-9db0-6cc1d7b0dde9
status: stable
description: Host Without Firewall. Alert means not complied. Sigma for Qualys vulnerability scanner. Scan type - Vulnerability Management.
references:
    - https://www.cisecurity.org/controls/cis-controls-list/
    - https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
    - https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
author: Alexandr Yampolskyi, SOC Prime
date: 2019/03/19
modified: 2022/10/05
# tags:
    # - CSC9
    # - CSC9.4
    # - NIST CSF 1.1 PR.AC-5
    # - NIST CSF 1.1 PR.AC-6
    # - NIST CSF 1.1 PR.AC-7
    # - NIST CSF 1.1 DE.AE-1
    # - ISO 27002-2013 A.9.1.2
    # - ISO 27002-2013 A.13.2.1
    # - ISO 27002-2013 A.13.2.2
    # - ISO 27002-2013 A.14.1.2
    # - PCI DSS 3.2 1.4
logsource:
    product: qualys
detection:
    selection:
        event.category: 'Security Policy'
        host.scan.vuln_name|contains: 'Firewall Product Not Detected'
    condition: selection
level: low

```