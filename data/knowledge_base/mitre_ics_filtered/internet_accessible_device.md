# MITRE ATT&CK for ICS: Internet Accessible Device

Type: attack-pattern
External IDs: T0883
URL: https://attack.mitre.org/techniques/T0883

## Description
Adversaries may gain access into industrial environments through systems exposed directly to the internet for remote access rather than through [External Remote Services](https://attack.mitre.org/techniques/T0822). Internet Accessible Devices are exposed to the internet unintentionally or intentionally without adequate protections. This may allow for adversaries to move directly into the control system network. Access onto these devices is accomplished without the use of exploits, these would be represented within the [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819) technique. Adversaries may leverage built in functions for remote access which may not be protected or utilize minimal legacy protections that may be targeted. (Citation: NCCIC January 2014) These services may be discoverable through the use of online scanning tools. In the case of the Bowman dam incident, adversaries leveraged access to the dam control network through a cellular modem. Access to the device was protected by password authentication, although the application was vulnerable to brute forcing. (Citation: NCCIC January 2014) (Citation: Danny Yadron December 2015) (Citation: Mark Thompson March 2016) In Trend Micros manufacturing deception operations adversaries were detected leveraging direct internet access to an ICS environment through the exposure of operational protocols such as Siemens S7, Omron FINS, and EtherNet/IP, in addition to misconfigured VNC access. (Citation: Stephen Hilt, Federico Maggi, Charles Perine, Lord Remorin, Martin Rsler, and Rainer Vosseler)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
