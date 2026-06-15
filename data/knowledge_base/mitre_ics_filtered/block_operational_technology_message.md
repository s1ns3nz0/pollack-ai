# MITRE ATT&CK for ICS: Block Operational Technology Message

Type: attack-pattern
External IDs: T1691
URL: https://attack.mitre.org/techniques/T1691

## Description
Adversaries may block messages between systems and devices in an OT/ICS environment to disrupt processes. Messages typically fall into two categories: (1) reporting messages that contain telemetry data about the current state of systems, devices, and processes and (2) command messages that contain instructions to control systems, devices, and processes. Both types of messages are critical for the proper functioning of industrial control processes and failure of the messages to reach their intended destinations could inhibit response functions or create an unsafe condition that could have physical impacts.(Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011)(Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016) Adversaries may block communications by either making modifications to software ([System Firmware](https://attack.mitre.org/techniques/T0857), [Module Firmware](https://attack.mitre.org/techniques/T0839), [Hooking](https://attack.mitre.org/techniques/T0874), and [Rootkit](https://attack.mitre.org/techniques/T0851)) and services ([Service Stop](https://attack.mitre.org/techniques/T0881), [Denial of Service](https://attack.mitre.org/techniques/T0814)) on systems and devices or by positioning themselves between systems and devices and intercepting and blocking the communications such as the case with an [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830) attack.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
