# UAV SOC Dataset Download Status

Last updated: 2026-06-11

## Summary

This project separates raw dataset storage from RAG-ready documents.

- Raw files go under `raw_data/`.
- Downloaded web/API metadata goes under `raw_docs/`.
- RAG-ready markdown documents go under `ragflow_ingest/` and `raw_docs/`.

## Dataset Status

| Dataset or source | Status | Local path | Notes |
|---|---|---|---|
| MITRE ATT&CK for ICS STIX | Downloaded | `raw_data/mitre_ics/ics-attack.json` | Full STIX JSON copied from `raw_docs/mitre_ics_attack.json`. |
| UAV NetworkCommunication | Downloaded | `raw_data/uav_networkcommunication/` | PCAP, PKL, and ZIP files downloaded from GitHub. Raw PCAP/PKL are not directly indexed; summaries are indexed. |
| IEC 62443 public materials | Downloaded partially | `raw_data/iec62443/` | Public overview HTML and a public ISA/GCA PDF were downloaded. Paid IEC standard text is not downloaded or copied. |
| Aissou GPS Spoofing Dataset | Metadata downloaded, raw XLSX blocked | `raw_docs/aissou_public_dataset.json` | Mendeley public API returned 3 files and download URLs. The actual file downloads redirect to S3 and repeatedly fail in this environment with SSL EOF/timeout. |
| UAV Attack Dataset | Metadata downloaded, raw ZIP blocked | `raw_docs/uav_attack_dataset_ieee_page.html` | IEEE page lists `UAVAttackData.zip` at 683.88 MB, but dataset files require IEEE DataPort login. |
| SOC Agent instruction dataset | Not applicable | N/A | This is not an external dataset. It must be generated from canonical events and RAG templates. |

## Aissou Files Identified

Source: `https://data.mendeley.com/public-api/datasets/z7dj3yyzt8`

| Filename | Size | File ID |
|---|---:|---|
| `GPS_Authentic_Data_3D_8_Channels.xlsx` | 105,617,965 bytes | `8302e52d-22ae-411d-8be3-4b0af3a76b12` |
| `GPS_Data_Simplified_2D_Feature_Map.xlsx` | 72,355,638 bytes | `67e5bd6e-1d2e-4a7d-bef0-248fda7c91a0` |
| `GPS_Dataset_3D_8_Channels_Authentic_and_Simulated.xlsx` | 106,419,311 bytes | `d2a812cb-e6e4-4701-a84a-8c5621023a12` |

The Mendeley ZIP API returned:

- URL: `https://prod-dcd-datasets-cache-zipfiles.s3.eu-west-1.amazonaws.com/z7dj3yyzt8-3.zip`
- Size: 259,021,422 bytes
- SHA256: `f3ba1d26e219b80c548d617674b735416d6e8a0700efb345639c857d85114d3a`

Download attempts failed because the S3 endpoint reached TCP connection but did
not complete stable TLS/data transfer in this environment.

## UAV Attack Dataset Access

Source: `https://ieee-dataport.org/open-access/uav-attack-dataset`

The page confirms:

- DOI: `10.21227/00dg-0d12`
- Format: CSV
- File listed: `UAVAttackData.zip`
- Size: 683.88 MB
- Access requirement: IEEE DataPort login, free IEEE account allowed.

Raw file download cannot be automated without a logged-in IEEE DataPort session
or user-provided authenticated download.

