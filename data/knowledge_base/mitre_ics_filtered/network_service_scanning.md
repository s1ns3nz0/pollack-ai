# MITRE ATT&CK for ICS: Network Service Scanning

Type: attack-pattern
External IDs: T0841
URL: https://attack.mitre.org/techniques/T0841

## Description
Network Service Scanning is the process of discovering services on networked systems. This can be achieved through a technique called port scanning or probing. Port scanning interacts with the TCP/IP ports on a target system to determine whether ports are open, closed, or filtered by a firewall. This does not reveal the service that is running behind the port, but since many common services are run on [https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml specific port numbers], the type of service can be assumed. More in-depth testing includes interaction with the actual service to determine the service type and specific version. One of the most-popular tools to use for Network Service Scanning is [https://nmap.org/ Nmap]. An adversary may attempt to gain information about a target device and its role on the network via Network Service Scanning techniques, such as port scanning. Network Service Scanning is useful for determining potential vulnerabilities in services on target devices. Network Service Scanning is closely tied to . Scanning ports can be noisy on a network. In some attacks, adversaries probe for specific ports using custom tools. This was specifically seen in the Triton and PLC-Blaster attacks.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
