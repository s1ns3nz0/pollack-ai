# RAGFlow Ingest Documents

This directory contains documents that are suitable for ingestion into RAGFlow.
It intentionally excludes raw PCAP, PKL, XLSX, ZIP, and large JSON files.

Recommended ingestion order:

1. Dataset cards and manifests.
2. IEC 62443 UAV response templates.
3. MITRE ATT&CK for ICS filtered technique documents.
4. Generated incident case documents.

Raw source files remain in `../raw_data/`.

