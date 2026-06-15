# MITRE ATT&CK for ICS: Serial Connection Enumeration

Type: attack-pattern
External IDs: T0854
URL: https://attack.mitre.org/techniques/T0854

## Description
Adversaries may perform serial connection enumeration to gather situational awareness after gaining access to devices in the OT network. Control systems devices often communicate to each other via various types of serial communication mediums. These serial communications are used to facilitate informational communication, as well as commands. Serial Connection Enumeration differs from I/O Module Discovery, as I/O modules are auxiliary systems to the main system, and devices that are connected via serial connection are normally discrete systems. While IT and OT networks may work in tandem, the exact structure of the OT network may not be discernible from the IT network alone. After gaining access to a device on the OT network, an adversary may be able to enumerate the serial connections. From this perspective, the adversary can see the specific physical devices to which the compromised device is connected to. This gives the adversary greater situational awareness and can influence the actions that the adversary can take in an attack.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
