# MITRE ATT&CK for ICS: Block Command Message

Type: attack-pattern
External IDs: T0803
URL: https://attack.mitre.org/techniques/T0803

## Description
Adversaries may block a command message from reaching its intended target to prevent command execution. In OT networks, command messages are sent to provide instructions to control system devices. A blocked command message can inhibit response functions from correcting a disruption or unsafe condition. (Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
