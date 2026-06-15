# MITRE ATT&CK for ICS: Screen Capture

Type: attack-pattern
External IDs: T0852
URL: https://attack.mitre.org/techniques/T0852

## Description
Adversaries may attempt to perform screen capture of devices in the control system environment. Screenshots may be taken of workstations, HMIs, or other devices that display environment-relevant process, device, reporting, alarm, or related data. These device displays may reveal information regarding the ICS process, layout, control, and related schematics. In particular, an HMI can provide a lot of important industrial process information. (Citation: ICS-CERT October 2017) Analysis of screen captures may provide the adversary with an understanding of intended operations and interactions between critical devices.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
