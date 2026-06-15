# MITRE ATT&CK for ICS: Modify Alarm Settings

Type: attack-pattern
External IDs: T0838
URL: https://attack.mitre.org/techniques/T0838

## Description
Adversaries may modify alarm settings to prevent alerts that may inform operators of their presence or to prevent responses to dangerous and unintended scenarios. Reporting messages are a standard part of data acquisition in control systems. Reporting messages are used as a way to transmit system state information and acknowledgements that specific actions have occurred. These messages provide vital information for the management of a physical process, and keep operators, engineers, and administrators aware of the state of system devices and physical processes. If an adversary is able to change the reporting settings, certain events could be prevented from being reported. This type of modification can also prevent operators or devices from performing actions to keep the system in a safe state. If critical reporting messages cannot trigger these actions then a [Impact](https://attack.mitre.org/tactics/TA0105) could occur. In ICS environments, the adversary may have to use [Alarm Suppression](https://attack.mitre.org/techniques/T0878) or contend with multiple alarms and/or alarm propagation to achieve a specific goal to evade detection or prevent intended responses from occurring. (Citation: Jos Wetzels, Marina Krotofil 2019) Methods of suppression often rely on modification of alarm settings, such as modifying in memory code to fixed values or tampering with assembly level instruction code.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
