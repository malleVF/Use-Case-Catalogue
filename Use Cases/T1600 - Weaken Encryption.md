---
created: 2020-10-19
last_modified: 2020-10-21
version: 1.0
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1600
platforms: Network
tags: [T1600, techniques, Defense_Evasion]
---

## Weaken Encryption

### Description

Adversaries may compromise a network device?s encryption capability in order to bypass encryption that would otherwise protect data communications. (Citation: Cisco Synful Knock Evolution)

Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.

Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as [Modify System Image](https://attack.mitre.org/techniques/T1601), [Reduce Key Space](https://attack.mitre.org/techniques/T1600/001), and [Disable Crypto Hardware](https://attack.mitre.org/techniques/T1600/002), an adversary can negatively effect and/or eliminate a device?s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts. (Citation: Cisco Blog Legacy Device Attacks)

### Detection

There is no documented method for defenders to directly identify behaviors that weaken encryption. Detection efforts may be focused on closely related adversary behaviors, such as [Modify System Image](https://attack.mitre.org/techniques/T1601). Some detection methods require vendor support to aid in investigation.

### Defenses Bypassed

Encryption

### Data Sources

  - File: File Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1600
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1600
```
