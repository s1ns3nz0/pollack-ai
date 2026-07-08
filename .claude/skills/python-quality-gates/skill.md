---
name: python-quality-gates
description: "Python 품질·테스트 게이트 설정 가이드. black/ruff/mypy/pytest의 pyproject 설정, CI 게이트 명령, 커버리지 임계값(전체/diff/핵심경로), pre-commit 정합성, 타입힌트·독스트링·예외처리 강제 기준을 제공하는 quality-gate·test-engineer 확장 스킬. '린트 게이트', '커버리지 임계값', 'mypy 설정', 'pytest 게이트' 등에 사용한다."
---

# Python Quality Gates — black/ruff/mypy/pytest 게이트 가이드

quality-gate·test-engineer 에이전트가 품질·테스트 게이트 설계 시 활용하는 설정·임계값 레퍼런스.
프로젝트의 `pyproject.toml`·`.claude/rules/python-conventions.md`와 정합을 유지한다.

## 대상 에이전트

`quality-gate`, `test-engineer` — 이 스킬의 설정/임계값을 게이트 설계에 직접 적용한다.

## 도구 역할

| 도구 | 역할 | CI 명령 | 차단 |
|------|------|---------|------|
| black | 포매터 | `black --check .` | O |
| ruff | 린터 + isort | `ruff check .` | O |
| mypy | 타입 검사 | `mypy .` | O |
| pytest | 테스트 | `pytest --tb=short` | O |
| pytest-cov | 커버리지 | `pytest --cov --cov-report=xml` | 임계 미달 시 O |

## pyproject 설정 기준 (프로젝트 현행)

```toml
[tool.black]
line-length = 88
target-version = ["py311"]

[tool.ruff]
line-length = 88
target-version = "py311"

[tool.ruff.lint]
# select 예: E,F,W,I(isort),B(bugbear),UP(pyupgrade),S(bandit-security)
[tool.ruff.lint.isort]
# 표준→서드파티→로컬 3그룹

[tool.mypy]
python_version = "3.11"   # ⚠️ 현행 3.12와 불일치 시 통일 필요
strict = true             # 권장: 점진 적용

[tool.pytest.ini_options]
# asyncio_mode = "auto" 권장(@pytest.mark.asyncio 사용 시)
```

> 주의: 프로젝트 `pyproject`에서 mypy `python_version=3.12` vs black/ruff `py311` 불일치가
> 관찰됨. 게이트 설계 시 런타임(`requires-python>=3.11`)에 맞춰 **통일을 제안**한다.

## 커버리지 임계값 게이트

| 항목 | 임계 | 정책 | 도구 |
|------|------|------|------|
| 전체 라인 | ≥ 80% | `--cov-fail-under=80` | pytest-cov |
| 신규 코드(diff) | ≥ 90% | diff-cover / PR 코멘트 | diff-cover |
| 핵심 경로(agents/, core/, tools/) | ≥ 85% | 모듈별 임계 | coverage |

도입 전략: 처음엔 경고(soft) → 안정화 후 차단(hard)으로 단계 상향.

## CI 게이트 잡 (GitHub Actions)

```yaml
lint:
  name: Lint & Type Check
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@<SHA>
    - uses: actions/setup-python@<SHA>
      with: { python-version: "3.11", cache: pip }
    - run: pip install -e ".[dev]"
    - run: black --check .
    - run: ruff check . --output-format=github
    - run: mypy .

test:
  needs: lint
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@<SHA>
    - uses: actions/setup-python@<SHA>
      with: { python-version: "3.11", cache: pip }
    - run: pip install -e ".[dev]"
    - run: pytest --tb=short --cov --cov-report=xml --cov-fail-under=80
    - uses: actions/upload-artifact@<SHA>
      with: { name: coverage, path: coverage.xml }
```

## pre-commit 정합성 (`.pre-commit-config.yaml`)

CI 잡과 pre-commit 훅이 **같은 버전·같은 규칙**을 쓰도록 정합을 유지한다.

| 훅 | CI 대응 | 비고 |
|----|---------|------|
| black | lint:black | 버전 핀 일치 |
| ruff | lint:ruff | 동일 select |
| mypy | lint:mypy | 동일 python_version |

## 컨벤션 강제 (도구로 못 잡는 것은 코드리뷰로)

| 규약 | 강제 방법 |
|------|----------|
| public 함수 타입힌트 | mypy(disallow_untyped_defs) |
| `Any` 금지 | mypy(disallow_any_explicit) + 리뷰 |
| Google 독스트링 | ruff(D 규칙, pydocstyle) + 리뷰 |
| `print()` 금지 | ruff(T20) |
| bare except 금지 | ruff(E722) |
| 와일드카드 임포트 | ruff(F403/F405) |
| 동기 블로킹(requests/sleep) in async | ruff(ASYNC) + 리뷰 |

## 테스트 설계 원칙 (test-engineer)

- 위치: 소스와 동일 경로 `__tests__/`, 함수 `test_{상황}_{기대결과}`
- 외부 API(Azure OpenAI/Sentinel)는 `AsyncMock`으로 mock, 실제 호출 금지
- 결정론: 시드 고정, LLM 응답 픽스처화, 플레이키는 quarantine 마커로 격리
- 피라미드: 단위 70 / 통합 25 / 도메인 회귀(G2) 5
