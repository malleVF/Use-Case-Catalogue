---
tags: [T1496, atomic_test]
filename: "[[T1496 - Resource Hijacking]]"
---
# T1496 - Resource Hijacking

## Atomic Test #1 - FreeBSD/macOS/Linux - Simulate CPU Load with Yes
This test simulates a high CPU load as you might observe during cryptojacking attacks.
End the test by using CTRL/CMD+C to break.

**Supported Platforms:** Linux, macOS


**auto_generated_guid:** 904a5a0e-fb02-490d-9f8d-0e256eb37549






#### Attack Commands: Run with `sh`! 


```sh
yes > /dev/null
```






<br/>
