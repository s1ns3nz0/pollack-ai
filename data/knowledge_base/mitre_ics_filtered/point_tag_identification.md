# MITRE ATT&CK for ICS: Point & Tag Identification

Type: attack-pattern
External IDs: T0861
URL: https://attack.mitre.org/techniques/T0861

## Description
Adversaries may collect point and tag values to gain a more comprehensive understanding of the process environment. Points may be values such as inputs, memory locations, outputs or other process specific variables. (Citation: Dennis L. Sloatman September 2016) Tags are the identifiers given to points for operator convenience. Collecting such tags provides valuable context to environmental points and enables an adversary to map inputs, outputs, and other values to their control processes. Understanding the points being collected may inform an adversary on which processes and values to keep track of over the course of an operation.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
