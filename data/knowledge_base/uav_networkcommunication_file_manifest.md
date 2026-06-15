# UAV NetworkCommunication File Manifest

Source repository:
https://github.com/naiksrinu/UAV_DataSet_NetworkCommunication

Downloaded raw data location:
`uav_soc_rag_poc/raw_data/uav_networkcommunication/`

Files:
- `UAV_WiFi_NetworkTraffic.pcap`
  - Size: about 710 KB.
  - Type: PCAP capture file.
  - RAG usage: do not index raw packets directly. Extract packet summaries,
    protocol counts, timestamps, attack windows, and unusual traffic descriptions.
- `gps_dataset.pkl`
  - Size: about 13 MB.
  - Type: Python pickle data. It appears to require `scapy` to unpickle in this
    environment.
  - RAG usage: convert into GPS/network event summaries after dependencies are
    available.
- `gps_dataset_attacks.zip`
  - Size: about 2 MB compressed.
  - Contains `gps_dataset_attacks.pkl`, about 334 MB uncompressed.
  - RAG usage: preserve as raw attack data; extract representative attack
    summaries later.
- `gps_dataset_attacks_PCAP.zip`
  - Size: about 2.1 MB compressed.
  - Contains `gps_dataset_attacks.pcap`, about 334 MB uncompressed.
  - RAG usage: preserve as raw GPS attack PCAP; extract packet-level summaries
    later.

Project interpretation:
This dataset supports network-side evidence for the UAV SOC Agent. It can help
separate GPS spoofing or GPS jamming evidence from Wi-Fi deauthentication,
jamming, packet loss, or generic GCS communication disruption. For RAG, the
correct representation is not raw packet payloads, but short incident-case
documents and extracted feature summaries.

