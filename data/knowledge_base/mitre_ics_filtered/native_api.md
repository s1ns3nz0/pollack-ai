# MITRE ATT&CK for ICS: Native API

Type: attack-pattern
External IDs: T0834
URL: https://attack.mitre.org/techniques/T0834

## Description
Adversaries may directly interact with the native OS application programming interface (API) to access system functions. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. (Citation: The MITRE Corporation May 2017) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations. Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as memcpy and direct operations on memory registers can be used to modify user and system memory space.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
