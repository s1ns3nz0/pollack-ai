# MITRE ATT&CK for ICS: Adversary-in-the-Middle

Type: attack-pattern
External IDs: T0830
URL: https://attack.mitre.org/techniques/T0830

## Description
Adversaries with privileged network access may seek to modify network traffic in real time using adversary-in-the-middle (AiTM) attacks. (Citation: Gabriel Sanchez October 2017) This type of attack allows the adversary to intercept traffic to and/or from a particular device on the network. If a AiTM attack is established, then the adversary has the ability to block, log, modify, or inject traffic into the communication stream. There are several ways to accomplish this attack, but some of the most-common are Address Resolution Protocol (ARP) poisoning and the use of a proxy. (Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) An AiTM attack may allow an adversary to perform the following attacks: [Block Reporting Message](https://attack.mitre.org/techniques/T0804), [Spoof Reporting Message](https://attack.mitre.org/techniques/T0856), [Modify Parameter](https://attack.mitre.org/techniques/T0836), [Unauthorized Command Message](https://attack.mitre.org/techniques/T0855)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
