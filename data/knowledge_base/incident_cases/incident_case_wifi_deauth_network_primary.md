# Incident Case: Wi-Fi Deauthentication or Jamming Suspected

Input signals:
- GCS link instability observed.
- Packet loss or deauthentication frames observed.
- GPS instability is absent or secondary.

Assessment:
Network-side UAV-GCS disruption is more likely than primary GPS spoofing.

Evidence:
- Communication channel indicators are abnormal.
- GPS-specific evidence is weak or missing.
- UAV control or telemetry path is affected.

MITRE ATT&CK for ICS candidates:
- Wireless Compromise
- Denial of Control
- Denial of View

IEC 62443-style response:
- Preserve PCAP and authentication logs.
- Isolate affected wireless/GCS communication conduit where operationally safe.
- Verify adjacent zone impact before restoring control paths.
