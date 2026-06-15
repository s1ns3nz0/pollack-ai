# UAV SOC Agent Dataset Plan

Project goal:
Build a SOC Agent that receives UAV/GPS/network security events and returns a
structured defensive assessment: judgement, confidence, evidence, MITRE ATT&CK
for ICS mapping, IEC 62443-style response, and next actions.

Recommended data roles:
- Aissou GPS Spoofing Dataset: GNSS spoofing evidence and GPS feature context.
- UAV NetworkCommunication: UAV-GCS network traffic context, Wi-Fi attacks,
  GPS jamming, and GPS spoofing descriptions.
- MITRE ATT&CK for ICS: attack tactic and technique mapping.
- IEC 62443 templates: zone/conduit response vocabulary.
- UAV Attack Dataset: optional telemetry source if access is confirmed.

Do not physically merge all raw datasets row-by-row.
Instead:
1. Extract useful evidence from each source.
2. Convert evidence into canonical UAV security events.
3. Attach attack labels and confidence rules.
4. Attach MITRE technique candidates.
5. Attach IEC 62443-style response templates.
6. Use the result for RAG documents and, later, small instruction tuning.

Canonical event fields:
- event_id
- asset_id
- zone
- telemetry_summary
- gnss_summary
- network_summary
- label
- confidence
- evidence
- mitre_ics_candidates
- iec62443_response

SOC Agent answer format:
1. Judgement
2. Confidence
3. Evidence
4. MITRE ATT&CK for ICS mapping
5. IEC 62443-style response
6. Next actions

