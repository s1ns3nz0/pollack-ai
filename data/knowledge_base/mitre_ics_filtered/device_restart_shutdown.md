# MITRE ATT&CK for ICS: Device Restart/Shutdown

Type: attack-pattern
External IDs: T0816
URL: https://attack.mitre.org/techniques/T0816

## Description
Adversaries may forcibly restart or shutdown a device in an ICS environment to disrupt and potentially negatively impact physical processes. Methods of device restart and shutdown exist in some devices as built-in, standard functionalities. These functionalities can be executed using interactive device web interfaces, CLIs, and network protocol commands. Unexpected restart or shutdown of control system devices may prevent expected response functions happening during critical states. A device restart can also be a sign of malicious device modifications, as many updates require a shutdown in order to take effect.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
