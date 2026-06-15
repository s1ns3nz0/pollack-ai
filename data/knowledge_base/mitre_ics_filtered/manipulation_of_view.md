# MITRE ATT&CK for ICS: Manipulation of View

Type: attack-pattern
External IDs: T0832
URL: https://attack.mitre.org/techniques/T0832

## Description
Adversaries may attempt to manipulate the information reported back to operators or controllers. This manipulation may be short term or sustained. During this time the process itself could be in a much different state than what is reported. (Citation: Corero) (Citation: Michael J. Assante and Robert M. Lee) (Citation: Tyson Macaulay) Operators may be fooled into doing something that is harmful to the system in a loss of view situation. With a manipulated view into the systems, operators may issue inappropriate control sequences that introduce faults or catastrophic failures into the system. Business analysis systems can also be provided with inaccurate data leading to bad management decisions.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
