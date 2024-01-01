---
created: 2020-03-02
last_modified: 2022-04-19
version: 1.1
tactics: Impact
url: https://attack.mitre.org/techniques/T1565
platforms: Linux, Windows, macOS
tags: [T1565, techniques, Impact]
---

## Data Manipulation

### Description

Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

### Detection

Where applicable, inspect important file hashes, locations, and modifications for suspicious/unexpected values. With some critical processes involving transmission of data, manual or out-of-band integrity checking may be useful for identifying manipulated data.

### Defenses Bypassed



### Data Sources

  - File: File Creation
  -  File: File Deletion
  -  File: File Metadata
  -  File: File Modification
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
  -  Process: OS API Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1565
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1565
```
