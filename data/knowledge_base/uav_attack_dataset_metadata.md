# UAV Attack Dataset Metadata

Source:
https://ieee-dataport.org/open-access/uav-attack-dataset

DOI:
10.21227/00dg-0d12

Observed access status:
The dataset page is public and marked Open Access, but raw dataset file access
requires IEEE DataPort login. The page states that open access dataset files are
available to logged-in users and that IEEE membership is not required.

Files listed on the page:
- `UAVAttackData.zip`
- Size: 683.88 MB
- Format listed: CSV

Dataset role for this project:
This dataset is valuable as a UAV telemetry/flight-log source. It can provide
evidence for flight anomalies such as benign flight, GPS spoofing, GPS jamming,
or other attack conditions. If the ZIP is obtained through a logged-in IEEE
session, it should be stored under `raw_data/uav_attack_dataset/` and converted
into canonical UAV security event summaries before RAG ingestion.

RAG usage:
Do not index the raw CSV rows directly. Convert them into event summaries such
as altitude changes, GPS instability, flight-mode changes, and attack labels.

