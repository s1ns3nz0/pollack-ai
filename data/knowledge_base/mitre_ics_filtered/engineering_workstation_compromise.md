# MITRE ATT&CK for ICS: Engineering Workstation Compromise

Type: attack-pattern
External IDs: T0818
URL: https://attack.mitre.org/techniques/T0818

## Description
Adversaries will compromise and gain control of an engineering workstation for Initial Access into the control system environment. Access to an engineering workstation may occur through or physical means, such as a Valid Accounts with privileged access or infection by removable media. A dual-homed engineering workstation may allow the adversary access into multiple networks. For example, unsegregated process control, safety system, or information system networks. An Engineering Workstation is designed as a reliable computing platform that configures, maintains, and diagnoses control system equipment and applications. Compromise of an engineering workstation may provide access to, and control of, other control system applications and equipment. In the Maroochy attack, the adversary utilized a computer, possibly stolen, with proprietary engineering software to communicate with a wastewater system.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
