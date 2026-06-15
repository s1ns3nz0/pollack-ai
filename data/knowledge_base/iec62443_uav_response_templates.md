# IEC 62443 UAV/OT Response Templates

Source:
- https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards

Document role:
IEC 62443 is not a UAV dataset. In this project it is used as a response and
architecture vocabulary for OT-style containment. The key concepts are zone,
conduit, security level, risk assessment, and controlled communication between
zones.

UAV interpretation:
- UAV Operations Zone: UAV assets, onboard telemetry sources, and mission
  execution components.
- GCS Control Zone: ground control station, operator interface, mission planning
  console, and control services.
- Telemetry/control conduit: communication path between UAV and GCS.
- Enterprise/SOC Zone: monitoring, logging, alerting, and incident response
  systems.

Response template for GPS spoofing or GPS jamming suspicion:
1. Preserve GPS, IMU, autopilot, and GCS communication logs.
2. Check failsafe, loiter, return-to-home, or manual-control policy.
3. Limit the affected UAV-GCS telemetry/control conduit if containment is
   required.
4. Review whether other assets in the same UAV Operations Zone show similar
   navigation anomalies.
5. Escalate to operator approval before any action that changes flight state.

Response template for suspected GCS network attack:
1. Confirm packet loss, deauthentication, jamming, or unusual control traffic.
2. Isolate the affected wireless/GCS communication conduit where operationally
   safe.
3. Preserve PCAP and authentication logs.
4. Verify whether the GPS anomaly is primary evidence or secondary to network
   disruption.
5. Assess adjacent zone impact before restoring normal control paths.

Important caution:
IEC 62443 public descriptions can guide templates, but the standard text itself
is not a raw dataset. Do not copy paid standard text into training data or RAG
documents. Use project-owned templates derived from public concepts.

