# MITRE ATT&CK for ICS: Modify Controller Tasking

Type: attack-pattern
External IDs: T0821
URL: https://attack.mitre.org/techniques/T0821

## Description
Adversaries may modify the tasking of a controller to allow for the execution of their own programs. This can allow an adversary to manipulate the execution flow and behavior of a controller. According to 61131-3, the association of a Task with a Program Organization Unit (POU) defines a task association. (Citation: IEC February 2013) An adversary may modify these associations or create new ones to manipulate the execution flow of a controller. Modification of controller tasking can be accomplished using a Program Download in addition to other types of program modification such as online edit and program append. Tasks have properties, such as interval, frequency and priority to meet the requirements of program execution. Some controller vendors implement tasks with implicit, pre-defined properties whereas others allow for these properties to be formulated explicitly. An adversary may associate their program with tasks that have a higher priority or execute associated programs more frequently. For instance, to ensure cyclic execution of their program on a Siemens controller, an adversary may add their program to the task, Organization Block 1 (OB1).

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
