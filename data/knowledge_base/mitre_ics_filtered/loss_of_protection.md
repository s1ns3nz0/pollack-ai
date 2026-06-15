# MITRE ATT&CK for ICS: Loss of Protection

Type: attack-pattern
External IDs: T0837
URL: https://attack.mitre.org/techniques/T0837

## Description
Adversaries may compromise protective system functions designed to prevent the effects of faults and abnormal conditions. This can result in equipment damage, prolonged process disruptions and hazards to personnel. Many faults and abnormal conditions in process control happen too quickly for a human operator to react to. Speed is critical in correcting these conditions to limit serious impacts such as Loss of Control and Property Damage. Adversaries may target and disable protective system functions as a prerequisite to subsequent attack execution or to allow for future faults and abnormal conditions to go unchecked. Detection of a Loss of Protection by operators can result in the shutdown of a process due to strict policies regarding protection systems. This can cause a Loss of Productivity and Revenue and may meet the technical goals of adversaries seeking to cause process disruptions.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
