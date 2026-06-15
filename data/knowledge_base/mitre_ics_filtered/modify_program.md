# MITRE ATT&CK for ICS: Modify Program

Type: attack-pattern
External IDs: T0889
URL: https://attack.mitre.org/techniques/T0889

## Description
Adversaries may modify or add a program on a controller to affect how it interacts with the physical process, peripheral devices and other hosts on the network. Modification to controller programs can be accomplished using a Program Download in addition to other types of program modification such as online edit and program append. Program modification encompasses the addition and modification of instructions and logic contained in Program Organization Units (POU) (Citation: IEC February 2013) and similar programming elements found on controllers. This can include, for example, adding new functions to a controller, modifying the logic in existing functions and making new calls from one function to another. Some programs may allow an adversary to interact directly with the native API of the controller to take advantage of obscure features or vulnerabilities.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
