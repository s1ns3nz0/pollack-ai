# MITRE ATT&CK for ICS: I/O Module Discovery

Type: attack-pattern
External IDs: T0824
URL: https://attack.mitre.org/techniques/T0824

## Description
Adversaries may use input/output (I/O) module discovery to gather key information about a control system device. An I/O module is a device that allows the control system device to either receive or send signals to other devices. These signals can be analog or digital, and may support a number of different protocols. Devices are often able to use attachable I/O modules to increase the number of inputs and outputs that it can utilize. An adversary with access to a device can use native device functions to enumerate I/O modules that are connected to the device. Information regarding the I/O modules can aid the adversary in understanding related control processes.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
