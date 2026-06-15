# MITRE ATT&CK for ICS: Location Identification

Type: attack-pattern
External IDs: T0825
URL: https://attack.mitre.org/techniques/T0825

## Description
Adversaries may perform location identification using device data to inform operations and targeted impact for attacks. Location identification data can come in a number of forms, including geographic location, location relative to other control system devices, time zone, and current time. An adversary may use an embedded global positioning system (GPS) module in a device to figure out the physical coordinates of a device. NIST SP800-82 recommends that devices utilize GPS or another location determining mechanism to attach appropriate timestamps to log entries (Citation: Guidance - NIST SP800-82). While this assists in logging and event tracking, an adversary could use the underlying positioning mechanism to determine the general location of a device. An adversary can also infer the physical location of serially connected devices by using serial connection enumeration. An adversary attempt to attack and cause Impact could potentially affect other control system devices in close proximity. Device local-time and time-zone settings can also provide adversaries a rough indicator of device location, when specific geographic identifiers cannot be determined from the system.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
