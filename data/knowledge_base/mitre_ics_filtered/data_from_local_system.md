# MITRE ATT&CK for ICS: Data from Local System

Type: attack-pattern
External IDs: T0893
URL: https://attack.mitre.org/techniques/T0893

## Description
Adversaries may target and collect data from local system sources, such as file systems, configuration files, or local databases. This can include sensitive data such as specifications, schematics, or diagrams of control system layouts, devices, and processes. Adversaries may do this using [Command-Line Interface](https://attack.mitre.org/techniques/T0807) or [Scripting](https://attack.mitre.org/techniques/T0853) techniques to interact with the file system to gather information. Adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T0802) on the local system.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
