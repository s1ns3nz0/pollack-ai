# MITRE ATT&CK for ICS: Block Reporting Message

Type: attack-pattern
External IDs: T0804
URL: https://attack.mitre.org/techniques/T0804

## Description
Adversaries may block or prevent a reporting message from reaching its intended target. In control systems, reporting messages contain telemetry data (e.g., I/O values) pertaining to the current state of equipment and the industrial process. By blocking these reporting messages, an adversary can potentially hide their actions from an operator. Blocking reporting messages in control systems that manage physical processes may contribute to system impact, causing inhibition of a response function. A control system may not be able to respond in a proper or timely manner to an event, such as a dangerous fault, if its corresponding reporting message is blocked. (Citation: Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011) (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
