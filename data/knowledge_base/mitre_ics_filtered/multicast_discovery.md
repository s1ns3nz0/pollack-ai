# MITRE ATT&CK for ICS: Multicast Discovery

Type: attack-pattern
External IDs: T0846.003
URL: https://attack.mitre.org/techniques/T0846/003

## Description
Adversaries may perform multicast discovery requests which is when one system or device sends messages to all systems and devices in a pre-defined group on a network (or subnet) and then waits for a response. If a response is received that means the system or device that responded is live and can communicate over that protocol. Multicast discovery tends to be stealthier than broadcast discovery because every system or device on the network (or subnet) is not being messaged. One common OT protocol that has a multicast discovery mechanism is the Process Field Network (PROFINET) Discovery and Configuration Protocol (DCP) with its Identify All requests.(Citation: Cisco Active Discovery)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
