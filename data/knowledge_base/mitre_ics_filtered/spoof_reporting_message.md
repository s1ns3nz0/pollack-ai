# MITRE ATT&CK for ICS: Spoof Reporting Message

Type: attack-pattern
External IDs: T0856
URL: https://attack.mitre.org/techniques/T0856

## Description
Adversaries may spoof reporting messages in control system environments for evasion and to impair process control. In control systems, reporting messages contain telemetry data (e.g., I/O values) pertaining to the current state of equipment and the industrial process. Reporting messages are important for monitoring the normal operation of a system or identifying important events such as deviations from expected values. If an adversary has the ability to Spoof Reporting Messages, they can impact the control system in many ways. The adversary can Spoof Reporting Messages that state that the process is operating normally, as a form of evasion. The adversary could also Spoof Reporting Messages to make the defenders and operators think that other errors are occurring in order to distract them from the actual source of a problem. (Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
