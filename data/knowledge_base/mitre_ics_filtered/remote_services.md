# MITRE ATT&CK for ICS: Remote Services

Type: attack-pattern
External IDs: T0886
URL: https://attack.mitre.org/techniques/T0886

## Description
Adversaries may leverage remote services to move between assets and network segments. These services are often used to allow operators to interact with systems remotely within the network, some examples are RDP, SMB, SSH, and other similar mechanisms. (Citation: Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer December 2017) (Citation: Dragos December 2017) (Citation: Joe Slowik April 2019) Remote services could be used to support remote access, data transmission, authentication, name resolution, and other remote functions. Further, remote services may be necessary to allow operators and administrators to configure systems within the network from their engineering or management workstations. An adversary may use this technique to access devices which may be dual-homed (Citation: Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer December 2017) to multiple network segments, and can be used for [Program Download](https://attack.mitre.org/techniques/T0843) or to execute attacks on control devices directly through [Valid Accounts](https://attack.mitre.org/techniques/T0859). Specific remote services (RDP & VNC) may be a precursor to enable [Graphical User Interface](https://attack.mitre.org/techniques/T0823) execution on devices such as HMIs or engineering workstation software. Based on incident data, CISA and FBI assessed that Chinese state-sponsored actors also compromised various authorized remote access channels, including systems designed to transfer data and/or allow access between corporate and ICS networks. (Citation: CISA AA21-201A Pipeline Intrusion July 2021)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
