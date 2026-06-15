# MITRE ATT&CK for ICS: Command-Line Interface

Type: attack-pattern
External IDs: T0807
URL: https://attack.mitre.org/techniques/T0807

## Description
Adversaries may utilize command-line interfaces (CLIs) to interact with systems and execute commands. CLIs provide a means of interacting with computer systems and are a common feature across many types of platforms and devices within control systems environments. (Citation: Enterprise ATT&CK January 2018) Adversaries may also use CLIs to install and run new software, including malicious tools that may be installed over the course of an operation. CLIs are typically accessed locally, but can also be exposed via services, such as SSH, Telnet, and RDP. Commands that are executed in the CLI execute with the current permissions level of the process running the terminal emulator, unless the command specifies a change in permissions context. Many controllers have CLI interfaces for management purposes.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
