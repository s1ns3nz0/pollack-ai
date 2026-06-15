# MITRE ATT&CK for ICS: Data from Information Repositories

Type: attack-pattern
External IDs: T0811
URL: https://attack.mitre.org/techniques/T0811

## Description
Adversaries may target and collect data from information repositories. This can include sensitive data such as specifications, schematics, or diagrams of control system layouts, devices, and processes. Examples of information repositories include reference databases in the process environment, as well as databases in the corporate network that might contain information about the ICS.(Citation: Cybersecurity & Infrastructure Security Agency March 2018) Information collected from these systems may provide the adversary with a better understanding of the operational environment, vendors used, processes, or procedures of the ICS. In a campaign between 2011 and 2013 against ONG organizations, Chinese state-sponsored actors searched document repositories for specific information such as, system manuals, remote terminal unit (RTU) sites, personnel lists, documents that included the string SCAD*, user credentials, and remote dial-up access information. (Citation: CISA AA21-201A Pipeline Intrusion July 2021)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
