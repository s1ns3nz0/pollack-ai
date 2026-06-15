# MITRE ATT&CK for ICS: External Remote Services

Type: attack-pattern
External IDs: T0822
URL: https://attack.mitre.org/techniques/T0822

## Description
Adversaries may leverage external remote services as a point of initial access into your network. These services allow users to connect to internal network resources from external locations. Examples are VPNs, Citrix, and other access mechanisms. Remote service gateways often manage connections and credential authentication for these services. (Citation: Daniel Oakley, Travis Smith, Tripwire) External remote services allow administration of a control system from outside the system. Often, vendors and internal engineering groups have access to external remote services to control system networks via the corporate network. In some cases, this access is enabled directly from the internet. While remote access enables ease of maintenance when a control system is in a remote area, compromise of remote access solutions is a liability. The adversary may use these services to gain access to and execute attacks against a control system network. Access to valid accounts is often a requirement. As they look for an entry point into the control system network, adversaries may begin searching for existing point-to-point VPN implementations at trusted third party networks or through remote support employee connections where split tunneling is enabled. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
