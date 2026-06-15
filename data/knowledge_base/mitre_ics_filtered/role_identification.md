# MITRE ATT&CK for ICS: Role Identification

Type: attack-pattern
External IDs: T0850
URL: https://attack.mitre.org/techniques/T0850

## Description
Adversaries may perform role identification of devices involved with physical processes of interest in a target control system. Control systems devices often work in concert to control a physical process. Each device can have one or more roles that it performs within that control process. By collecting this role-based data, an adversary can construct a more targeted attack. For example, a power generation plant may have unique devices such as one that monitors power output of a generator and another that controls the speed of a turbine. Examining devices roles allows the adversary to observe how the two devices work together to monitor and control a physical process. Understanding the role of a target device can inform the adversary's decision on what action to take, in order to cause Impact and influence or disrupt the integrity of operations. Furthermore, an adversary may be able to capture control system protocol traffic. By studying this traffic, the adversary may be able to determine which devices are outstations, and which are masters. Understanding of master devices and their role within control processes can enable the use of Rogue Master Device

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
