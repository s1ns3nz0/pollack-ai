# 예선 MVP 상세 런북 - UAV ATT&CK 15전술 CACAO + PB 효과학습 폐루프

## 0. 한 줄 요약

이 런북은 팀이 정의한 `UAV ATT&CK` 15개 전술 전체가 CACAO 2.0 대응
플레이북으로 커버되고, 신뢰 관측이 다음 대응 설명을 바꾸는 폐루프까지 동작함을
예선 심사자에게 증명한다.

## 1. 데모 스토리

첫 번째 incident 의 신뢰 관측이 `OutcomeProbeAgent` 를 통해 actor profile 과
playbook 효과점수로 적립된다. 같은 actor 의 다음 incident 에서 `ResponseAgent`
와 `ReportAgent` 가 해당 PB 효과를 표면한다. 즉, 단순 탐지 데모가 아니라
관측 결과가 다음 대응 권고와 보고 evidence 를 바꾸는 AI SOC 폐루프를 보여준다.

데모 핵심 메시지는 다음과 같다.

- `UAV ATT&CK` 15전술 전체가 CACAO 2.0 manual-response 플레이북으로 연결된다.
- 대응은 자동 실행이 아니라 analyst-facing 권고로 표면되어 no-hack-back 원칙을 지킨다.
- 고임무영향 전술은 mission-risk gate 로 HITL 보수 분기를 탄다.
- 손상 자산의 mission continuity 를 Response 단계에서 즉시 표면한다.
- 신뢰 관측 기반 PB 효과학습이 다음 response/report 에 증거로 남는다.

## 2. 기준 파일

| 목적 | 파일 |
| --- | --- |
| UAV ATT&CK 15전술 기준 | `data/attack_coverage.yaml` |
| CACAO 2.0 플레이북 카탈로그 | `core/policy/cacao-playbooks.yaml` |
| 7D 방어 source_ref | `core/policy/coa-matrix.yaml` |
| 축출/복구/검증 source_ref | `core/policy/recovery-matrix.yaml` |
| CACAO 로더/검증기 | `core/cacao.py` |
| Response 배선 | `agents/response_agent.py` |
| Resilience/mission continuity 정책 | `core/policy/degradation-matrix.yaml` |
| Report PB 효과 표면 | `agents/report_agent.py` |
| learning-loop E2E 테스트 | `tests/__tests__/test_demo_learning_loop.py` |
| 보고서용 카탈로그 브리프 | `docs/hackathon/uav-attack-cacao-full-catalog.md` |

## 3. 사전 조건

로컬 개발 환경에서 아래 명령이 실행 가능해야 한다.

```bash
python --version
pytest --version
```

외부 API 키나 Azure 연결은 이 런북 검증에 필요하지 않다. 테스트는 deterministic
in-memory store 와 fixture 기반으로 동작한다.

## 4. 빠른 검증 명령

심사 직전에는 아래 두 명령을 순서대로 실행한다.

```bash
pytest tests/__tests__/test_cacao.py tests/__tests__/test_response_cacao.py tests/__tests__/test_demo_learning_loop.py -q
pytest tests/__tests__/test_demo_learning_loop.py -q
```

전체 제출 전에는 프로젝트 규칙에 맞춰 아래 전체 검증을 실행한다.

```bash
black .
ruff check .
mypy .
pytest
```

## 5. UAV ATT&CK 15전술 CACAO 풀 카탈로그

`core/policy/cacao-playbooks.yaml` 는 `data/attack_coverage.yaml` 의 15개 전술을
모두 포함한다. 각 플레이북은 `contain -> eradicate -> recover -> verify -> adapt`
단계를 가진다.

| 순서 | UAV ATT&CK 전술 | 플레이북 ID | 데모 설명 |
| --- | --- | --- | --- |
| 1 | Reconnaissance | `playbook--uav-recon-0001` | 정찰 출처 식별, 허니 엔드포인트 유인, 노출면 최소화 |
| 2 | ResourceDevelopment | `playbook--uav-rdev-0001` | 스테이징 인프라 IOC 차단, 허니 문서 접촉 출처 격리 |
| 3 | InitialAccess | `playbook--uav-ia-0001` | 비인가 원격서비스 차단, MFA/화이트리스트 강제 |
| 4 | Execution | `playbook--uav-exec-0001` | 미인가 명령 시퀀스 탐지, 실행 세션 격리 |
| 5 | Persistence | `playbook--uav-persist-0001` | 펌웨어 서명 검증, 비행금지 게이트, 재이미징 |
| 6 | PrivilegeEscalation | `playbook--uav-privesc-0001` | 특권 세션 종료, 상승 토큰 폐기, 최소권한 복구 |
| 7 | StealthEvasion | `playbook--uav-stealth-0001` | 불변 로그 보존, 은폐 도구 격리, 감사 체인 복원 |
| 8 | Discovery | `playbook--uav-disc-0001` | 무선 스니핑 탐지, 조회권한 회수, 디코이 토폴로지 |
| 9 | LateralMovement | `playbook--uav-lm-0001` | 횡적확산 세션 격리, 자격증명 회전, 백업 GCS 이관 |
| 10 | Collection | `playbook--uav-coll-0001` | 수집 채널 격리, 센서/영상 링크 암호화 복구 |
| 11 | CommandAndControl | `playbook--uav-c2-0001` | 미인가 C2 차단, 대체 링크 전환, 키 롤오버 |
| 12 | Exfiltration | `playbook--uav-exfil-0001` | 유출 채널 차단, egress 정책 복원, DLP 강화 |
| 13 | ImpairProcessControl | `playbook--uav-ipc-0001` | 제어 파라미터 쓰기 차단, 센서퓨전 항법 복구 |
| 14 | InhibitResponseFunction | `playbook--uav-irf-0001` | 알람 무결성 복구, 링크 재라우팅, 대역외 감시 |
| 15 | Impact | `playbook--uav-impact-0001` | 비인가 명령 거부, HITL failsafe, 안전정지/임무 이관 |

## 6. 카탈로그 검증 절차

아래 테스트는 카탈로그가 단순 YAML 목록이 아니라 실행 전 검증되는 정책 객체임을
보여준다.

```bash
pytest tests/__tests__/test_cacao.py -q
```

기대되는 검증 항목은 다음과 같다.

| 검증 항목 | 의미 |
| --- | --- |
| 15개 전술 로드 | `UAV ATT&CK` 전체 전술 키와 카탈로그 전술 키가 일치 |
| CACAO 필수 필드 | `type`, `spec_version`, `workflow_start`, `start/end` 존재 |
| no-exec | command 는 `manual` 만 허용, machine agent/실행형 extra key 거부 |
| phase coverage | 모든 플레이북이 contain/eradicate/recover/adapt 포함 |
| recovery verify | 모든 플레이북이 recover 검증 step 포함 |
| IR 통제 태그 | action step 에 NIST IR 라벨 존재, 폐지된 IR-10 거부 |
| source_ref 해결 | COA/Recovery matrix 의 실제 셀을 참조 |
| mission gate | 고임무영향 전술은 mission-risk 기반 HITL 보수 분기 포함 |

## 7. Response 배선 검증 절차

아래 테스트는 alert scenario tactic 이 CACAO 카탈로그 선택으로 이어지는지 확인한다.

```bash
pytest tests/__tests__/test_response_cacao.py -q
```

주요 기대값은 다음과 같다.

| 시나리오 | 기대 동작 |
| --- | --- |
| `Impact` + 높은 mission risk | `playbook--uav-impact-0001` 선택, conservative/HITL 분기 |
| `Impact` + 낮은 mission risk | 같은 플레이북 선택, auto 분기 |
| mission risk 없음 | fail-safe 로 conservative/HITL 분기 |
| `Discovery` | `playbook--uav-disc-0001` 선택, CACAO steps 표면 |
| `AUTOPILOT` 손상 | `ABORT` resilience, 안전착륙/기동불능화 fallback 표면 |
| `AUTOPILOT` + key terrain | `mission_context.operator_posture=ABORT_SAFE_LAND` 표면 |
| 카탈로그 미주입 | 기존 `defense_playbook` fallback 유지 |
| actor PB outcome 있음 | `mission_risk_note` 에 과거 PB 효과 표면 |

## 8. Resilience-aware Response Overlay

Response 단계는 CACAO 플레이북만 고르는 것이 아니라, 손상 자산의 임무 지속성도
같이 표면한다. 기준 정책은 `core/policy/degradation-matrix.yaml` 이다.

| 자산 | 등급 | 손실 능력 | Response fallback |
| --- | --- | --- | --- |
| `GNSS` | `SUSTAINED` | 위성항법 정확도 | INS/관성항법 단독 전환 + 마지막 신뢰좌표 기준 항법 지속 |
| `C2_LINK` | `MINIMAL` | 실시간 지상 지휘통제 | 자율 페일세이프 모드 + 대체 링크 시도, 미복구 시 RTB |
| `AUTOPILOT` | `ABORT` | 비행제어 | 검증 이미지 미확보 시 즉시 안전착륙/기동 불능화 |
| `AI_SOC` | `SUSTAINED` | AI SOC 자동 판정 | 정책 엔진 단독 모드 + 운용자 수동 검토 병행 |

Response 결과 샘플은 다음과 같다.

```text
CACAO: playbook--uav-impact-0001
Mission branch: conservative
Resilience: ABORT
Capability lost: 비행제어(기본 비행 안정성)
Fallback: 검증 이미지 미확보 시 비행 불가 — 즉시 안전착륙/기동 불능화
Mission context: asset=AUTOPILOT | phase=terminal | posture=ABORT_SAFE_LAND
```

데모에서 강조할 문장은 다음과 같다.

```text
Response 는 공격 전술만 보지 않고, 손상 자산이 임무를 계속 지탱할 수 있는지까지
판정해 대응 권고에 붙인다. 또한 key terrain, 의존자산, fallback 을 구조화한
mission_context 로 운용자 posture 를 바로 제시한다.
```

## 9. PB 효과학습 폐루프 검증 절차

아래 명령이 예선 데모의 핵심 smoke test 다.

```bash
pytest tests/__tests__/test_demo_learning_loop.py -q
```

테스트 내부 흐름은 다음과 같다.

1. `InMemoryObservationSource` 에 `team-red` actor 의 `Impact` 관측을 넣는다.
2. `OutcomeProbeAgent` 가 신뢰 관측을 읽어 actor profile 과 PB 효과점수를 적립한다.
3. 같은 actor 의 다음 incident 에 대해 `ResponseAgent` 가 CACAO `Impact` 플레이북을 고른다.
4. `ResponseAgent` 가 과거 PB 효과를 `mission_risk_note` 에 붙인다.
5. `ReportAgent` 가 actor 별 PB 효과 top-3 를 `guardrail_flags` 에 남긴다.

고정 기대값은 다음과 같다.

| 증거 | 기대값 |
| --- | --- |
| `worker_report.auto_applied` | `2` |
| `ResponseAgent` `mission_risk_note` | `PB 효과 playbook--uav-impact-0001=0.30(1)` |
| `ReportAgent` `guardrail_flags` | `actor[team-red] PB 효과 top-3: playbook--uav-impact-0001=0.30(1)` |

## 10. 심사 시연 순서

1. 먼저 카탈로그 브리프를 보여준다.

```text
docs/hackathon/uav-attack-cacao-full-catalog.md
```

2. `data/attack_coverage.yaml` 에 15전술이 있음을 설명한다.
3. `core/policy/cacao-playbooks.yaml` 에 15개 플레이북이 있음을 설명한다.
4. `pytest tests/__tests__/test_cacao.py -q` 로 카탈로그 검증을 보여준다.
5. `pytest tests/__tests__/test_response_cacao.py -q` 로 response 배선을 보여준다.
6. `pytest tests/__tests__/test_demo_learning_loop.py -q` 로 PB 효과학습 폐루프를 보여준다.
7. 보고서에는 `uav-attack-cacao-full-catalog.md` 의 표와 문구를 붙인다.

## 11. 데모 중 말할 포인트

- "저희 기준은 공식 ICS 전술 축을 그대로 가져온 것이 아니라, 팀이 작성한 UAV
  ATT&CK 15전술 매트릭스입니다."
- "각 전술은 CACAO 2.0 플레이북으로 대응되고, 모든 command 는 manual 권고라
  자동 공격/역공격이 없습니다."
- "Impact, ImpairProcessControl, InhibitResponseFunction 같은 고임무영향 전술은
  mission-risk gate 를 통해 자동 대응 대신 HITL 보수 분기로 갑니다."
- "Response 단계는 CACAO 대응뿐 아니라 자산 손상 시 임무 지속 가능성, 손실 능력,
  fallback 까지 같이 표면합니다."
- "PB 효과점수는 alert 본문을 믿고 적립하지 않고, `OutcomeProbe` 신뢰 관측 경로로만
  적립합니다."
- "이전 대응 결과가 다음 Response/Report 설명에 반영되므로, SOC 가 관측으로
  학습하는 폐루프를 갖습니다."

## 12. 보고서 삽입 문구

본 플랫폼은 팀이 정의한 UAV ATT&CK 15개 전술 전 범위에 대해 CACAO 2.0 기반
대응 플레이북을 제공한다. 각 플레이북은 봉쇄, 축출, 복구, 검증, 적응 단계를
포함하며, `core/cacao.py` 검증기로 no-exec, NIST IR 태그, COA/Recovery source_ref,
workflow 참조 무결성을 확인한다. 대응 명령은 자동 실행이 아닌 analyst-facing
manual command 로 제한하여 no-hack-back 원칙을 유지한다. Response 단계는 손상
자산의 mission continuity 를 함께 평가해 `SUSTAINED`, `MINIMAL`, `ABORT` 등급과
fallback 을 즉시 제시한다. 또한 OutcomeProbe 기반 신뢰 관측을 통해 actor 별
playbook 효과를 적립하고, 다음 Response/Report 단계에서 해당 효과를 evidence 로
표면한다.

## 13. 문제 해결

| 증상 | 확인할 것 |
| --- | --- |
| `load_playbooks()` 실패 | 새 플레이북의 `source_ref` 가 `coa-matrix.yaml` 또는 `recovery-matrix.yaml` 에 존재하는지 확인 |
| `IR-10` 관련 실패 | NIST SP 800-53 Rev5 기준에서 IR-10 은 허용하지 않으므로 `IR-4(11)` 또는 `IR-1`~`IR-9` 사용 |
| `Discovery` 가 fallback 으로 감 | `tests/__tests__/test_response_cacao.py` 의 scenario tactic map 과 카탈로그 ID 확인 |
| resilience note 가 비어 있음 | alert 의 `asset_id` 가 `degradation-matrix.yaml` 의 assets 키와 일치하는지 확인 |
| PB 효과가 report 에 안 보임 | `ActorWriteGate`, `ActorPlaybookOutcomeGate`, `ActorReadGate` 가 같은 store 를 공유하는지 확인 |
| full test 중 old fixture 실패 | 이제 `Reconnaissance` 는 미정의 전술이 아니므로 unknown fixture 는 `UnknownTactic` 사용 |

## 14. 완료 기준

아래 조건을 모두 만족하면 예선 제출용 런북 기준 완료다.

- `core/policy/cacao-playbooks.yaml` 이 15개 UAV ATT&CK 전술을 모두 포함한다.
- `tests/__tests__/test_cacao.py` 가 15개 플레이북 로드와 검증을 통과한다.
- `tests/__tests__/test_response_cacao.py` 가 CACAO 선택과 fallback 경로를 모두 통과한다.
- `tests/__tests__/test_response_cacao.py` 가 response resilience overlay 를 검증한다.
- `tests/__tests__/test_demo_learning_loop.py` 가 PB 효과학습 폐루프를 통과한다.
- `docs/hackathon/uav-attack-cacao-full-catalog.md` 의 표를 보고서에 넣을 수 있다.
- `black . && ruff check . && mypy . && pytest` 가 통과한다.

## 방어 대시보드 실행

대시보드는 `dashboard.snapshot.v1` JSON을 파일 리플레이 또는 SSE로 표시한다. 기본 리플레이
디렉터리는 `demo_snapshots/`다.

```bash
uvicorn app.dashboard:app --host 127.0.0.1 --port 8088
```

브라우저에서 `http://127.0.0.1:8088/`을 연다.

검증 포인트:

- 좌측은 alert 목록이 아니라 story 카드가 1급으로 표시된다.
- UAV ATT&CK navigator는 observed/current/predicted/gap 상태를 같은 matrix에 표시한다.
- BLUF 카드는 `SOCReport.commander_brief`의 confidence/caveat를 숨기지 않는다.
- topology는 `core/policy/asset-topology.yaml` 기준 UAS 자산 구성도를 표시한다.
- `LIVE` 버튼은 `/events` SSE snapshot을 같은 렌더 경로로 표시한다.
