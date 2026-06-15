# MITRE ATT&CK for ICS: Replication Through Removable Media

Type: attack-pattern
External IDs: T0847
URL: https://attack.mitre.org/techniques/T0847

## Description
Adversaries may move onto systems, such as those separated from the enterprise network, by copying malware to removable media which is inserted into the control systems environment. The adversary may rely on unknowing trusted third parties, such as suppliers or contractors with access privileges, to introduce the removable media. This technique enables initial access to target devices that never connect to untrusted networks, but are physically accessible. Operators of the German nuclear power plant, Gundremmingen, discovered malware on a facility computer not connected to the internet. (Citation: Kernkraftwerk Gundremmingen April 2016) (Citation: Trend Micro April 2016) The malware included Conficker and W32.Ramnit, which were also found on eighteen removable disk drives in the facility. (Citation: Christoph Steitz, Eric Auchard April 2016) (Citation: Catalin Cimpanu April 2016) (Citation: Peter Dockrill April 2016) (Citation: Lee Mathews April 2016) (Citation: Sean Gallagher April 2016) (Citation: Dark Reading Staff April 2016) The plant has since checked for infection and cleaned up more than 1,000 computers. (Citation: BBC April 2016) An ESET researcher commented that internet disconnection does not guarantee system safety from infection or payload execution. (Citation: ESET April 2016)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
