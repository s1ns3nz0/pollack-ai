# MITRE ATT&CK for ICS: Autorun Image

Type: attack-pattern
External IDs: T0895
URL: https://attack.mitre.org/techniques/T0895

## Description
Adversaries may leverage AutoRun functionality or scripts to execute malicious code. Devices configured to enable AutoRun functionality or legacy operating systems may be susceptible to abuse of these features to run malicious code stored on various forms of removeable media (i.e., USB, Disk Images [.ISO]). Commonly, AutoRun or AutoPlay are disabled in many operating systems configurations to mitigate against this technique. If a device is configured to enable AutoRun or AutoPlay, adversaries may execute code on the device by mounting the removable media to the device, either through physical or virtual means. This may be especially relevant for virtual machine environments where disk images may be dynamically mapped to a guest system on a hypervisor. An example could include an adversary gaining access to a hypervisor through the management interface to modify a virtual machine’s hardware configuration. They could then deploy an iso image with a malicious AutoRun script to cause the virtual machine to automatically execute the code contained on the disk image. This would enable the execution of malicious code within a virtual machine without needing any prior remote access to that system.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
