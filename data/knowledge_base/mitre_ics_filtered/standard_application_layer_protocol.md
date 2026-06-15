# MITRE ATT&CK for ICS: Standard Application Layer Protocol

Type: attack-pattern
External IDs: T0869
URL: https://attack.mitre.org/techniques/T0869

## Description
Adversaries may establish command and control capabilities over commonly used application layer protocols such as HTTP(S), OPC, RDP, telnet, DNP3, and modbus. These protocols may be used to disguise adversary actions as benign network traffic. Standard protocols may be seen on their associated port or in some cases over a non-standard port. Adversaries may use these protocols to reach out of the network for command and control, or in some cases to other infected devices within the network.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
