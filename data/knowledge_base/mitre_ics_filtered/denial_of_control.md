# MITRE ATT&CK for ICS: Denial of Control

Type: attack-pattern
External IDs: T0813
URL: https://attack.mitre.org/techniques/T0813

## Description
Adversaries may cause a denial of control to temporarily prevent operators and engineers from interacting with process controls. An adversary may attempt to deny process control access to cause a temporary loss of communication with the control device or to prevent operator adjustment of process controls. An affected process may still be operating during the period of control loss, but not necessarily in a desired state. (Citation: Corero) (Citation: Michael J. Assante and Robert M. Lee) (Citation: Tyson Macaulay) In the 2017 Dallas Siren incident operators were unable to disable the false alarms from the Office of Emergency Management headquarters. (Citation: Mark Loveless April 2017)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
