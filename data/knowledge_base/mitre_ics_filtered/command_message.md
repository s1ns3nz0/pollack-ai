# MITRE ATT&CK for ICS: Command Message

Type: attack-pattern
External IDs: T1692.001
URL: https://attack.mitre.org/techniques/T1692/001

## Description
Adversaries may send unauthorized command messages to instruct control system assets to perform actions outside of their intended functionality, or without the logical preconditions to trigger their expected function. Command messages are used in ICS networks to give direct instructions to control systems devices. If an adversary can send an unauthorized command message to a control system, then it can instruct the control systems device to perform an action outside the normal bounds of the device's actions. An adversary could potentially instruct a control systems device to perform an action that will cause an [Impact](https://attack.mitre.org/tactics/TA0105).(Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) In the Dallas Siren incident, adversaries were able to send command messages to activate tornado alarm systems across the city without an impending tornado or other disaster.(Citation: Zack Whittaker April 2017)(Citation: Benjamin Freed March 2019)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
