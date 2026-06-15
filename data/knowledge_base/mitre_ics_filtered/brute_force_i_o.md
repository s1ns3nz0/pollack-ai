# MITRE ATT&CK for ICS: Brute Force I/O

Type: attack-pattern
External IDs: T0806
URL: https://attack.mitre.org/techniques/T0806

## Description
Adversaries may repetitively or successively change I/O point values to perform an action. Brute Force I/O may be achieved by changing either a range of I/O point values or a single point value repeatedly to manipulate a process function. The adversary's goal and the information they have about the target environment will influence which of the options they choose. In the case of brute forcing a range of point values, the adversary may be able to achieve an impact without targeting a specific point. In the case where a single point is targeted, the adversary may be able to generate instability on the process function associated with that particular point. Adversaries may use Brute Force I/O to cause failures within various industrial processes. These failures could be the result of wear on equipment or damage to downstream equipment.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
