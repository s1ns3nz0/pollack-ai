# UAV ATT&CK 15전술 CACAO 대응 플레이북 풀 카탈로그

## 요약

팀이 정의한 `UAV ATT&CK` 매트릭스(`data/attack_coverage.yaml`)의 15개 전술을
전부 CACAO 2.0 대응 플레이북으로 매핑했다. 각 플레이북은 권고전용 `manual`
command 만 포함하며, 봉쇄(contain) → 축출(eradicate) → 복구(recover) →
검증(verify) → 적응(adapt) 단계를 가진다.

## 카탈로그

| 순서 | UAV ATT&CK 전술 | CACAO 플레이북 ID | 핵심 대응 |
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

## 검증 근거

- `core/policy/cacao-playbooks.yaml`: CACAO 2.0 플레이북 본문.
- `core/policy/coa-matrix.yaml`: 전술별 7D 방어 옵션 source_ref.
- `core/policy/recovery-matrix.yaml`: 전술별 축출/복구/검증 source_ref.
- `core/policy/degradation-matrix.yaml`: 손상 자산별 mission continuity 와 fallback.
- `tests/__tests__/test_cacao.py`: 15개 전술 전체 로드, phase coverage,
  no-exec, source_ref, IR 통제 태그 검증.
- `tests/__tests__/test_response_cacao.py`: 전술 기반 CACAO 선택과 ResponseAgent 배선 검증.

## Response Resilience Overlay

Response 단계는 선택된 CACAO 플레이북에 손상 자산의 mission continuity 와
mission context card 를 덧붙인다. 예를 들어 `AUTOPILOT` 손상은 `ABORT` 로 표면되며,
fallback 은 "검증 이미지 미확보 시 즉시 안전착륙/기동 불능화" 로 제시된다.
`mission_context` 는 key terrain, 의존 자산, METT-TC factor, fallback 을 구조화하고
`operator_posture=ABORT_SAFE_LAND` 같은 운용 태세를 별도 필드로 낸다. 따라서 대응
권고는 전술뿐 아니라 임무 지속 가능성과 운용 판단까지 반영한다.

## 보고서 문구

본 플랫폼은 팀이 정의한 UAV ATT&CK 15개 전술 전 범위에 대해 CACAO 2.0 기반
대응 플레이북을 제공한다. 모든 플레이북은 자동 실행이 아닌 analyst-facing
manual command 로 표현되어 no-hack-back 원칙을 유지하며, 임무영향 전술은
mission-risk gate 를 통해 보수적 HITL 분기로 fail-safe 처리한다. 또한 Response
단계에서 손상 자산의 mission continuity, fallback, mission context card 를 함께
표면해, 임무 지속성 관점의 대응 우선순위와 운용자 posture 를 제시한다.
