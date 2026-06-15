# MITRE ATT&CK for ICS: Hooking

Type: attack-pattern
External IDs: T0874
URL: https://attack.mitre.org/techniques/T0874

## Description
Adversaries may hook into application programming interface (API) functions used by processes to redirect calls for execution and privilege escalation means. Windows processes often leverage these API functions to perform tasks that require reusable system resources. Windows API functions are typically stored in dynamic-link libraries (DLLs) as exported functions. (Citation: Enterprise ATT&CK) One type of hooking seen in ICS involves redirecting calls to these functions via import address table (IAT) hooking. IAT hooking uses modifications to a process IAT, where pointers to imported API functions are stored. (Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
