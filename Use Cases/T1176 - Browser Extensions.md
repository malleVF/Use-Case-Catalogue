---
created: 2018-01-16
last_modified: 2022-04-20
version: 1.2
tactics: Persistence
url: https://attack.mitre.org/techniques/T1176
platforms: Linux, Windows, macOS
tags: [T1176, techniques, Persistence]
---

## Browser Extensions

### Description

Adversaries may abuse Internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.(Citation: Wikipedia Browser Extension)(Citation: Chrome Extensions Definition)

Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners.(Citation: Malicious Chrome Extension Numbers) Depending on the browser, adversaries may also manipulate an extension's update url to install updates from an adversary controlled server or manipulate the mobile configuration file to silently install additional extensions.

Previous to macOS 11, adversaries could silently install browser extensions via the command line using the <code>profiles</code> tool to install malicious <code>.mobileconfig</code> files. In macOS 11+, the use of the <code>profiles</code> tool can no longer install configuration profiles, however <code>.mobileconfig</code> files can be planted and installed with user interaction.(Citation: xorrior chrome extensions macOS)

Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence.(Citation: Chrome Extension Crypto Miner)(Citation: ICEBRG Chrome Extensions)(Citation: Banker Google Chrome Extension Steals Creds)(Citation: Catch All Chrome Extension)

There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions.(Citation: Stantinko Botnet) There have also been similar examples of extensions being used for command & control.(Citation: Chrome Extension C2 Malware)

### Detection

Inventory and monitor browser extension installations that deviate from normal, expected, and benign extensions. Process and network monitoring can be used to detect browsers communicating with a C2 server. However, this may prove to be a difficult way of initially detecting a malicious extension depending on the nature and volume of the traffic it generates.

Monitor for any new items written to the Registry or PE files written to disk. That may correlate with browser extension installation.

On macOS, monitor the command line for usage of the profiles tool, such as <code>profiles install -type=configuration</code>. Additionally, all installed extensions maintain a <code>plist</code> file in the <code>/Library/Managed Preferences/username/</code> directory. Ensure all listed files are in alignment with approved extensions.(Citation: xorrior chrome extensions macOS)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  Network Traffic: Network Connection Creation
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1176
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1176
```
