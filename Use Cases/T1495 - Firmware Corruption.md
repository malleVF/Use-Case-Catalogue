---
created: 2019-04-12
last_modified: 2022-08-31
version: 1.2
tactics: Impact
url: https://attack.mitre.org/techniques/T1495
platforms: Linux, Network, Windows, macOS
tags: [T1495, techniques, Impact]
---

## Firmware Corruption

### Description

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.

In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable.(Citation: dhs_threat_to_net_devices)(Citation: cisa_malware_orgs_ukraine) Depending on the device, this attack may also result in [Data Destruction](https://attack.mitre.org/techniques/T1485). 

### Detection

System firmware manipulation may be detected.(Citation: MITRE Trustworthy Firmware Measurement) Log attempts to read/write to BIOS and compare against known patching behavior.

### Defenses Bypassed



### Data Sources

  - Firmware: Firmware Modification
### Detection Rule

```query
tag: detection_rule
tag: T1495
```

### Rule Testing

```query
tag: atomic_test
tag: T1495
```
