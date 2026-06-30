# KB — RAGFlow 지식베이스 소스

`scripts/ingest_kb.py` 가 이 폴더를 RAGFlow 데이터셋에 적재한다.
**하위 폴더명 = KbCategory(메타데이터 category)** 이므로 폴더 구조를 지킬 것.

| 폴더 | 범주 | 용도 |
|---|---|---|
| `incident_cases/` | incident_cases | 과거 인시던트/대응 회고 |
| `attack_techniques/` | attack_techniques | MITRE ATT&CK for ICS 기법 노트 |
| `standards/` | standards | IEC 62443 등 대응 표준 |
| `datasets/` | datasets | uav-sim-env 실측 베이스라인 |

적재: `python scripts/ingest_kb.py`  (설정: RAGFLOW_API_TOKEN/DATASET_ID)
