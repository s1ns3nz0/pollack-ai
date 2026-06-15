# MITRE ATT&CK for ICS: Service Stop

Type: attack-pattern
External IDs: T0881
URL: https://attack.mitre.org/techniques/T0881

## Description
Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. (Citation: Enterprise ATT&CK) Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct Data Destruction. (Citation: Enterprise ATT&CK)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
