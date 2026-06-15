# MITRE ATT&CK for ICS: Wireless Compromise

Type: attack-pattern
External IDs: T0860
URL: https://attack.mitre.org/techniques/T0860

## Description
Adversaries may perform wireless compromise as a method of gaining communications and unauthorized access to a wireless network. Access to a wireless network may be gained through the compromise of a wireless device. (Citation: Alexander Bolshev, Gleb Cherbov July 2014) (Citation: Alexander Bolshev March 2014) Adversaries may also utilize radios and other wireless communication devices on the same frequency as the wireless network. Wireless compromise can be done as an initial access vector from a remote distance. A Polish student used a modified TV remote controller to gain access to and control over the Lodz city tram system in Poland. (Citation: John Bill May 2017) (Citation: Shelley Smith February 2008) The remote controller device allowed the student to interface with the trams network to modify track settings and override operator control. The adversary may have accomplished this by aligning the controller to the frequency and amplitude of IR control protocol signals. (Citation: Bruce Schneier January 2008) The controller then enabled initial access to the network, allowing the capture and replay of tram signals. (Citation: John Bill May 2017)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
