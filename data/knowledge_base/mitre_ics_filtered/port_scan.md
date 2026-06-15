# MITRE ATT&CK for ICS: Port Scan

Type: attack-pattern
External IDs: T0846.001
URL: https://attack.mitre.org/techniques/T0846/001

## Description
Adversaries may perform a port scan on a system, device, or network to identify live hosts, enumerate open ports and running services, identify operating systems, and map out the network.(Citation: NIST SP 800-82r3) The results of a port scan may inform adversary [Discovery](https://attack.mitre.org/tactics/TA0102), [Lateral Movement](https://attack.mitre.org/tactics/TA0109), and vulnerability exploitation decisions ([Exploitation for Evasion](https://attack.mitre.org/techniques/T0820), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866)). Some common tools for executing a port scan include `nmap`, `netcat`, and the Advanced Port Scanner.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
