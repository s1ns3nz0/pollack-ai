# UAV AI SOC — NIST AI RMF × OSCAL 컴플라이언스

NIST AI RMF 1.0(AI 100-1)의 통제항목을 **OSCAL 1.1.2** 머신리더블 포맷으로 구체화하고,
이 플랫폼의 실제 통제(CI/CD 게이트·AI 레드팀·공급망·관측성·거버넌스)를 매핑해 **추적 관리**한다.

## 디렉토리

```
compliance/oscal/
├── catalog/        nist-ai-rmf-catalog.json    — AI RMF 72개 서브카테고리 (OSCAL 카탈로그)
├── profile/        uav-soc-ai-rmf-profile.json — 플랫폼이 채택한 35개 통제 (테일러드 베이스라인)
├── component-definition/ uav-soc-components.json — 8개 플랫폼 컴포넌트 → 통제 구현
├── ssp/            uav-soc-ssp.json            — 시스템 보안계획(구현현황: implemented/partial/planned)
├── poam/           uav-soc-poam.json           — 미흡/계획 통제의 갭 추적(Plan of Action & Milestones)
├── dashboard/      index.html + data.js        — 인터랙티브 추적 대시보드
├── build_oscal.py  단일 소스 생성기 (이 파일들을 모두 생성)
└── README.md
```

## 모델 관계 (OSCAL 레이어)

```
catalog (통제 정의: AI RMF 72)
   └─ profile (선택·테일러링: 35개 채택)
        ├─ component-definition (컴포넌트가 무엇을 충족하는가)
        └─ ssp (시스템에서 어떻게 구현되었는가 + 상태)
             └─ poam (구현 갭과 마일스톤)
```

## 현재 상태 (생성 시점)

- 전체 72개 서브카테고리 중 **35개 채택**(프로파일)
- 구현 15 · 부분 19 · 계획 1
- 나머지 37개는 카탈로그에 존재하나 현재 범위 밖(미대응) — 대시보드에서 확인

## 추적 관리 워크플로

1. **상태 갱신**: `build_oscal.py`의 `MAPPINGS` 리스트에서 통제별 상태(implemented/partial/planned)·
   서술·증거를 수정한다. (단일 소스)
2. **재생성**: `python compliance/oscal/build_oscal.py compliance/oscal`
3. **커밋**: 생성된 JSON + data.js를 git에 커밋 → 변경 이력으로 컴플라이언스 추세 추적
4. **대시보드 확인**: `compliance/oscal/dashboard/index.html`을 브라우저로 열기
5. **갭 관리**: POA&M(`poam/`)의 partial/planned 항목을 백로그로 운영

> CI 연계(선택): 이 생성기를 나이틀리로 돌려 상태 변화를 PR로 올리거나, OSCAL 유효성 검사를
> 게이트로 추가할 수 있다.

## 검증

OSCAL 공식 도구로 스키마 검증 가능:

```bash
# compliance-trestle (Python)
pip install compliance-trestle
trestle validate -f compliance/oscal/catalog/nist-ai-rmf-catalog.json
trestle validate -f compliance/oscal/ssp/uav-soc-ssp.json

# 또는 OSCAL CLI / oscal-js
```

JSON well-formed 확인:
```bash
python -c "import json,glob;[json.load(open(f)) for f in glob.glob('compliance/oscal/**/*.json',recursive=True)]"
```

## 매핑된 플랫폼 컴포넌트

| 컴포넌트 | 대표 통제 |
|---------|----------|
| AI Red Team Gate (PyRIT/ATLAS) | MEASURE 2.7, 2.6, 3.1, 3.2, GOVERN 4.3 |
| Supply Chain Integrity (SBOM/OIDC/서명) | GOVERN 6.1, MAP 4.1, MANAGE 3.1 |
| Observability (Prometheus/Grafana) | MEASURE 2.4, MANAGE 4.1, 3.2 |
| Deployment & GitOps (AKS/ArgoCD) | MANAGE 2.4, MAP 3.5 |
| Runtime Defense Guardrails | MAP 4.2, MEASURE 2.6, 2.9 |
| CI/CD Pipeline | MEASURE 2.1, 2.3, MANAGE 1.3 |
| Incident Response | MANAGE 4.3, 2.3, GOVERN 4.3 |
| Governance & Policy | GOVERN 1.x, 2.1, MAP 1.x |

## 출처

- NIST AI 100-1 (AI RMF 1.0): https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- OSCAL 1.1.2: https://pages.nist.gov/OSCAL/
- 서브카테고리 원문은 NIST AI 100-1 Tables 1–4에서 추출(verbatim).
