# Incident Case: GPS Spoofing Suspected with Normal GCS Link

Input signals:
- UAV altitude drop observed.
- GPS signal instability observed.
- IMU/GPS position divergence observed.
- GCS link status is normal.

Assessment:
GPS spoofing or GPS jamming is more likely than generic GCS network failure.

Evidence:
- Navigation anomaly is concentrated in GPS/GNSS behavior.
- Independent navigation estimate diverges from GPS position.
- GCS link remains normal, reducing likelihood of pure network outage.

MITRE ATT&CK for ICS candidates:
- Wireless Compromise
- Spoofed Data
- Impair Process Control

IEC 62443-style response:
- Preserve GPS, IMU, autopilot, and GCS communication logs.
- Check failsafe, loiter, return-to-home, or manual-control policy.
- Limit affected UAV-GCS telemetry/control conduit if containment is required.
- Review other assets in the same UAV Operations Zone.
