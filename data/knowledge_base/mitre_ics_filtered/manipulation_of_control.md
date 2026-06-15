# MITRE ATT&CK for ICS: Manipulation of Control

Type: attack-pattern
External IDs: T0831
URL: https://attack.mitre.org/techniques/T0831

## Description
Adversaries may manipulate physical process control within the industrial environment. Methods of manipulating control can include changes to set point values, tags, or other parameters. Adversaries may manipulate control systems devices or possibly leverage their own, to communicate with and command physical control processes. The duration of manipulation may be temporary or longer sustained, depending on operator detection. Methods of Manipulation of Control include: * Man-in-the-middle * Spoof command message * Changing setpoints A Polish student used a remote controller device to interface with the Lodz city tram system in Poland. (Citation: John Bill May 2017) (Citation: Shelley Smith February 2008) (Citation: Bruce Schneier January 2008) Using this remote, the student was able to capture and replay legitimate tram signals. As a consequence, four trams were derailed and twelve people injured due to resulting emergency stops. (Citation: Shelley Smith February 2008) The track controlling commands issued may have also resulted in tram collisions, a further risk to those on board and nearby the areas of impact. (Citation: Bruce Schneier January 2008)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
