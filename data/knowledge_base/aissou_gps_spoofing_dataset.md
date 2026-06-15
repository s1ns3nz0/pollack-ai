# Aissou GPS Spoofing Dataset

Source: https://data.mendeley.com/datasets/z7dj3yyzt8/3

Dataset role:
This dataset is used as the GNSS/GPS spoofing evidence source for a UAV SOC Agent.
It is useful for explaining why GPS signal instability, abnormal GPS receiver
features, or position anomalies may indicate GPS spoofing rather than a generic
system failure.

Known dataset characteristics:
- Public Mendeley dataset.
- Title: A DATASET for GPS Spoofing Detection on Unmanned Aerial System.
- GPS receiver feature dataset for spoofing detection.
- Includes normal GPS signal cases and spoofing attack cases.
- Described as using 8-channel GPS receiver data and 13 extracted features.
- Includes multiple spoofing attack types, including simplistic, intermediate,
  and sophisticated spoofing scenarios.
- License is reported as CC BY 4.0 on the Mendeley dataset page.

How it should be used in this project:
- Do not put raw numeric rows directly into the RAG store.
- Convert rows or dataset descriptions into incident evidence summaries.
- Use it to support labels such as gps_spoofing, gnss_spoofing,
  gps_signal_degradation, position_jump, and receiver_feature_anomaly.

Example RAG evidence:
GPS spoofing can appear as abnormal GPS receiver features, degraded signal
quality, position anomalies, or divergence between GNSS position and independent
navigation estimates. In a UAV context, this evidence becomes stronger when the
GCS link remains normal and the anomaly is concentrated in the navigation signal.

