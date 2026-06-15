# MITRE ATT&CK for ICS: Rogue Master

Type: attack-pattern
External IDs: T0848
URL: https://attack.mitre.org/techniques/T0848

## Description
Adversaries may setup a rogue master to leverage control server functions to communicate with outstations. A rogue master can be used to send legitimate control messages to other control system devices, affecting processes in unintended ways. It may also be used to disrupt network communications by capturing and receiving the network traffic meant for the actual master. Impersonating a master may also allow an adversary to avoid detection. In the case of the 2017 Dallas Siren incident, adversaries used a rogue master to send command messages to the 156 distributed sirens across the city, either through a single rogue transmitter with a strong signal, or using many distributed repeaters. (Citation: Bastille April 2017) (Citation: Zack Whittaker April 2017)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
