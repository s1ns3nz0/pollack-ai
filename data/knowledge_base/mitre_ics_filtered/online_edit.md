# MITRE ATT&CK for ICS: Online Edit

Type: attack-pattern
External IDs: T0843.002
URL: https://attack.mitre.org/techniques/T0843/002

## Description
Adversaries may execute an online edit of a PLC to update parts of an existing program. It does not require stopping the PLC which allows it to continue running during transfer and reconfiguration without interruption to process control. Adversaries may leverage this approach to minimize downtime and evade detection. The ability to perform an online edit to the PLC typically relies on access to a workstation with the vendor-specific PLC programming software installed.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
