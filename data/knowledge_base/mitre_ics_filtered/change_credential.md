# MITRE ATT&CK for ICS: Change Credential

Type: attack-pattern
External IDs: T0892
URL: https://attack.mitre.org/techniques/T0892

## Description
Adversaries may modify software and device credentials to prevent operator and responder access. Depending on the device, the modification or addition of this password could prevent any device configuration actions from being accomplished and may require a factory reset or replacement of hardware. These credentials are often built-in features provided by the device vendors as a means to restrict access to management interfaces. An adversary with access to valid or hardcoded credentials could change the credential to prevent future authorized device access. Change Credential may be especially damaging when paired with other techniques such as Modify Program, Data Destruction, or Modify Controller Tasking. In these cases, a device’s configuration may be destroyed or include malicious actions for the process environment, which cannot not be removed through normal device configuration actions. Additionally, recovery of the device and original configuration may be difficult depending on the features provided by the device. In some cases, these passwords cannot be removed onsite and may require that the device be sent back to the vendor for additional recovery steps. A chain of incidents occurred in Germany, where adversaries locked operators out of their building automation system (BAS) controllers by enabling a previously unset BCU key. (Citation: German BAS Lockout Dec 2021)

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
