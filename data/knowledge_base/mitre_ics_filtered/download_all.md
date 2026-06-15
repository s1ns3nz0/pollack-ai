# MITRE ATT&CK for ICS: Download All

Type: attack-pattern
External IDs: T0843.001
URL: https://attack.mitre.org/techniques/T0843/001

## Description
Adversaries may execute a full program download to a PLC to overwrite the entire PLC program and configuration to deploy a new project or make major changes. This typically requires stopping the PLC and adversely impacting control processes. The ability to perform a full program download to the PLC typically relies on access to a workstation with the vendor-specific PLC programming software installed.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
