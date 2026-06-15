# MITRE ATT&CK for ICS: Broadcast Discovery

Type: attack-pattern
External IDs: T0846.002
URL: https://attack.mitre.org/techniques/T0846/002

## Description
Adversaries may perform broadcast discovery requests to enumerate systems and devices on a network. Broadcast discovery works by one system or device sending messages to all systems and devices on a network (or subnet) and then waiting for a response. If a response is received that means the system or device that responded is live and can communicate over that protocol. Adversaries may leverage different protocols supported on the network for sending broadcast messages. Some common OT protocols that have broadcast discovery mechanisms are Building Automation and Control Network (BACNet) Who-Is requests, Common Industrial Protocol (CIP) List Identity User Datagram Protocol (UDP) broadcast requests, and Siemens S7 broadcast identification requests.(Citation: Broadcasting BACnet)(Citation: Cisco Active Discovery)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
