# MITRE ATT&CK for ICS: Data Historian Compromise

Type: attack-pattern
External IDs: T0810
URL: https://attack.mitre.org/techniques/T0810

## Description
Adversaries may compromise and gain control of a data historian to gain a foothold into the control system environment. Access to a data historian may be used to learn stored database archival and analysis information on the control system. A dual-homed data historian may provide adversaries an interface from the IT environment to the OT environment. Dragos has released an updated analysis on CrashOverride that outlines the attack from the ICS network breach to payload delivery and execution. (Citation: Industroyer - Dragos - 201810) The report summarized that CrashOverride represents a new application of malware, but relied on standard intrusion techniques. In particular, new artifacts include references to a Microsoft Windows Server 2003 host, with a SQL Server. Within the ICS environment, such a database server can act as a data historian. Dragos noted a device with this role should be "expected to have extensive connections" within the ICS environment. Adversary activity leveraged database capabilities to perform reconnaissance, including directory queries and network connectivity checks. Permissions Required: Administrator Contributors: Joe Slowik - Dragos

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
