---
title: "BPFtrace Unsafe Option Usage"
status: "test"
created: "2022/02/11"
last_modified: ""
tags: [execution, t1059_004, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## BPFtrace Unsafe Option Usage

### Description

Detects the usage of the unsafe bpftrace option

```yml
title: BPFtrace Unsafe Option Usage
id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: test
description: Detects the usage of the unsafe bpftrace option
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
author: Andreas Hunkeler (@Karneades)
date: 2022/02/11
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: 'bpftrace'
        CommandLine|contains: '--unsafe'
    condition: selection
falsepositives:
    - Legitimate usage of the unsafe option
level: medium

```
