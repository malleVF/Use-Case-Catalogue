---
title: "Suspicious Parent Double Extension File Execution"
status: "experimental"
created: "2023/01/06"
last_modified: "2023/02/28"
tags: [defense_evasion, t1036_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Parent Double Extension File Execution

### Description

Detect execution of suspicious double extension files in ParentCommandLine

```yml
title: Suspicious Parent Double Extension File Execution
id: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
related:
    - id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 # Image/CommandLine
      type: derived
status: experimental
description: Detect execution of suspicious double extension files in ParentCommandLine
references:
    - https://www.virustotal.com/gui/file/7872d8845a332dce517adae9c3389fde5313ff2fed38c2577f3b498da786db68/behavior
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bluebottle-banks-targeted-africa
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/06
modified: 2023/02/28
tags:
    - attack.defense_evasion
    - attack.t1036.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - ParentImage|endswith:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
              - '.doc.js'
              - '.docx.js'
              - '.xls.js'
              - '.xlsx.js'
              - '.ppt.js'
              - '.pptx.js'
              - '.rtf.js'
              - '.pdf.js'
              - '.txt.js'
        - ParentCommandLine|contains:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
              - '.doc.js'
              - '.docx.js'
              - '.xls.js'
              - '.xlsx.js'
              - '.ppt.js'
              - '.pptx.js'
              - '.rtf.js'
              - '.pdf.js'
              - '.txt.js'
    condition: selection
falsepositives:
    - Unknown
level: high

```