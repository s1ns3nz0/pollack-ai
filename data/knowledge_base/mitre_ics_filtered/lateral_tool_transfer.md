# MITRE ATT&CK for ICS: Lateral Tool Transfer

Type: attack-pattern
External IDs: T0867
URL: https://attack.mitre.org/techniques/T0867

## Description
Adversaries may transfer tools or other files from one system to another to stage adversary tools or other files over the course of an operation. (Citation: Enterprise ATT&CK) Copying of files may also be performed laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares. (Citation: Enterprise ATT&CK) In control systems environments, malware may use SMB and other file sharing protocols to move laterally through industrial networks.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
