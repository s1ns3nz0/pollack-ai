# MITRE ATT&CK for ICS: Connection Proxy

Type: attack-pattern
External IDs: T0884
URL: https://attack.mitre.org/techniques/T0884

## Description
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications. The definition of a proxy can also be expanded to encompass trust relationships between networks in peer-to-peer, mesh, or trusted connections between networks consisting of hosts or systems that regularly communicate with each other. The network may be within a single organization or across multiple organizations with trust relationships. Adversaries could use these types of relationships to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. (Citation: Enterprise ATT&CK January 2018)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
