# MITRE ATT&CK for ICS: Wi-Fi

Type: attack-pattern
External IDs: T1695.003
URL: https://attack.mitre.org/techniques/T1695/003

## Description
Adversaries may block access to Wi-Fi communications to prevent messages from reaching target systems and devices. Wi-Fi connections allow for communications between IT and OT systems and devices. Blocking Wi-Fi communications may also block command and reporting messages.(Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) An adversary may block Wi-Fi communications by disabling network interfaces, [Service Stop](https://attack.mitre.org/techniques/T0881), conducting an [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830) attack and dropping the network traffic, or by jamming the Wi-Fi signal.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
