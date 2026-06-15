# MITRE ATT&CK for ICS: I/O Image

Type: attack-pattern
External IDs: T0877
URL: https://attack.mitre.org/techniques/T0877

## Description
Adversaries may seek to capture process values related to the inputs and outputs of a PLC. During the scan cycle, a PLC reads the status of all inputs and stores them in an image table. (Citation: Nanjundaiah, Vaidyanath) The image table is the PLCs internal storage location where values of inputs/outputs for one scan are stored while it executes the user program. After the PLC has solved the entire logic program, it updates the output image table. The contents of this output image table are written to the corresponding output points in I/O Modules. The Input and Output Image tables described above make up the I/O Image on a PLC. This image is used by the user program instead of directly interacting with physical I/O. (Citation: Spenneberg, Ralf 2016) Adversaries may collect the I/O Image state of a PLC by utilizing a devices [Native API](https://attack.mitre.org/techniques/T0834) to access the memory regions directly. The collection of the PLCs I/O state could be used to replace values or inform future stages of an attack.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
