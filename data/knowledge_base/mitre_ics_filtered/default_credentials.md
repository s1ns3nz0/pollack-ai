# MITRE ATT&CK for ICS: Default Credentials

Type: attack-pattern
External IDs: T0812
URL: https://attack.mitre.org/techniques/T0812

## Description
Adversaries may leverage manufacturer or supplier set default credentials on control system devices. These default credentials may have administrative permissions and may be necessary for initial configuration of the device. It is general best practice to change the passwords for these accounts as soon as possible, but some manufacturers may have devices that have passwords or usernames that cannot be changed. (Citation: Keith Stouffer May 2015) Default credentials are normally documented in an instruction manual that is either packaged with the device, published online through official means, or published online through unofficial means. Adversaries may leverage default credentials that have not been properly modified or disabled.

## UAV SOC Use
Use this technique as a candidate mapping when UAV/GPS/network evidence matches the described adversary behavior. Do not treat it as a sensor label by itself.
