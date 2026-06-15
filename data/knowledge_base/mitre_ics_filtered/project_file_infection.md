# MITRE ATT&CK for ICS: Project File Infection

Type: attack-pattern
External IDs: T0873
URL: https://attack.mitre.org/techniques/T0873

## Description
Adversaries may attempt to infect project files with malicious code. These project files may consist of objects, program organization units, variables such as tags, documentation, and other configurations needed for PLC programs to function.(Citation: Beckhoff) Using built in functions of the engineering software, adversaries may be able to download an infected program to a PLC in the operating environment enabling further [Execution](https://attack.mitre.org/tactics/TA0104) and [Persistence](https://attack.mitre.org/tactics/TA0110) techniques.(Citation: PLCdev) Adversaries may export their own code into project files with conditions to execute at specific intervals.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011) Malicious programs allow adversaries control of all aspects of the process enabled by the PLC. Once the project file is downloaded to a PLC the workstation device may be disconnected with the infected project file still executing.(Citation: PLCdev)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
