---
cssclasses: wide-page
---

## Detection Rules

Grouped by MITRE ATT&CK tactics:

>[!info]- Reconnaissance
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #Reconnaissance 
>```

>[!info]- Resource Development
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #Resource_Development  
>```

>[!info]- Initial Access
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #initial_access  
>```

>[!info]- Execution
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #execution  
>```

>[!info]- Persistence
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #persistence  
>```

>[!info]- Privilege Escalation
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #privilege_escalation  
>```

>[!info]- Defense Evasion
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #defense_evasion  
>```

>[!info]- Credential Access
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #credential_access  
>```

>[!info]- Discovery
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #discovery  
>```

>[!info]- Lateral Movement
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #lateral_movement  
>```

>[!info]- Collection
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #collection  
>```

>[!info]- Command and Control
>```dataview
>TABLE
>sstatus, level, created, last_modified
>FROM "Detection Rules" AND #command_and_control  
>```

>[!info]- Exfiltration
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #exfiltration  
>```

>[!info]- Impact
>```dataview
>TABLE
>status, level, created, last_modified
>FROM "Detection Rules" AND #impact  
>```