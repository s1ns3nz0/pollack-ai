# MITRE ATT&CK for ICS: Modify Firmware

Type: attack-pattern
External IDs: T1693
URL: https://attack.mitre.org/techniques/T1693

## Description
Firmware is low-level software embedded in hardware that enables systems and devices to function properly and is commonly found in ICS environments. Adversaries may modify firmware on a system or device by installing malicious or vulnerable versions that enable them to achieve objectives such as [Persistence](https://attack.mitre.org/tactics/TA0110), [Impair Process Control](https://attack.mitre.org/tactics/TA0106), and [Inhibit Response Function](https://attack.mitre.org/tactics/TA0107). Adversaries may modify system and device firmware by using the built-in firmware update functionality which may support local or remote installation. The malicious or vulnerable firmware may be delivered via [Replication Through Removable Media](https://attack.mitre.org/techniques/T0847), [Supply Chain Compromise](https://attack.mitre.org/techniques/T0862), or [Remote Services](https://attack.mitre.org/techniques/T0886). Once installed, the malicious or vulnerable firmware could be used to provide [Rootkit](https://attack.mitre.org/techniques/T0851) and [Hooking](https://attack.mitre.org/techniques/T0874) functionality, [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890), or [Denial of Service](https://attack.mitre.org/techniques/T0814).(Citation: Basnight, Zachry, et al.)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
