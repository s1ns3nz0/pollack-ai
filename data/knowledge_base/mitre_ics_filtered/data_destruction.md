# MITRE ATT&CK for ICS: Data Destruction

Type: attack-pattern
External IDs: T0809
URL: https://attack.mitre.org/techniques/T0809

## Description
Adversaries may perform data destruction over the course of an operation. The adversary may drop or create malware, tools, or other non-native files on a target system to accomplish this, potentially leaving behind traces of malicious activities. Such non-native files and other data may be removed over the course of an intrusion to maintain a small footprint or as a standard part of the post-intrusion cleanup process. (Citation: Enterprise ATT&CK January 2018) Data destruction may also be used to render operator interfaces unable to respond and to disrupt response functions from occurring as expected. An adversary may also destroy data backups that are vital to recovery after an incident. Standard file deletion commands are available on most operating system and device interfaces to perform cleanup, but adversaries may use other tools as well. Two examples are Windows Sysinternals SDelete and Active@ Killdisk.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
