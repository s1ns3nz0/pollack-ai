# MITRE ATT&CK for ICS: Unauthorized Message

Type: attack-pattern
External IDs: T1692
URL: https://attack.mitre.org/techniques/T1692

## Description
Adversaries may send unauthorized messages to ICS systems and devices to evade defenses or manipulate processes. Unauthorized messages can be categorized as either reporting messages that contain telemetry data about the current state of systems, devices, and processes or as command messages which instruct systems and devices on how to operate. By injecting unauthorized messages, adversaries can make it appear as if everything is working correctly when it isn’t, trigger alarms to misdirect personnel or impact processes, and manipulate controls to disrupt processes.(Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) Adversaries may send unauthorized messages in an ICS environment using software found within the environment (living-off-the-land, vendor-specific interfaces, etc.), custom tooling leveraging OT protocols and libraries, or by positioning themselves between systems and devices and injecting messages into the communications such as the case with an [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830) attack.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
