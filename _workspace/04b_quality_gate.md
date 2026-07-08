# 품질 게이트 & 코드리뷰 설계 (UAV AI SOC)

**작성자**: quality-gate
**버전**: 1.0
**원칙**: black/ruff/mypy를 CI 차단형 게이트로 강제, `.claude/rules/python-conventions.md` 모든 항목 자동 강제 가능 형태로, pyproject 단일 소스(SSOT)로 pre-commit/CI/로컬 명령 일치

---

## 0. 요약

- **현행 진단**: black/ruff/mypy 세팅은 기본 골격은 갖춰져 있으나 ruff에 `D/T20/E722/PT/PTH/RUF` 등 다수 규칙 미선택, mypy `disallow_any_explicit` 미명시(`strict=true`에 포함되지 않는 옵션), CI 잡이 lint 한 잡에 lint+typecheck 혼합, pre-commit과 CI 명령 드리프트 위험(`ruff --fix` vs CI `ruff check`), 독스트링 커버리지/복잡도 게이트 미존재.
- **강화안**:
  - ruff: `D(pydocstyle/google)`, `T20(print)`, `PT(pytest)`, `PTH(pathlib)`, `RUF`, `ASYNC`, `C90(McCabe<=10)`, `TID(tidy imports)`, `SIM`, `N(naming)`, `PL(pylint subset)` 추가
  - mypy: `disallow_any_explicit=true` + `disallow_any_decorated=true` + `disallow_any_unimported=true` 추가
  - python_version 불일치(black/ruff=py311 vs mypy=py312) 통일 권고 (mypy `python_version=3.11`로 변경 또는 black/ruff target을 py312로 통일)
  - CI 잡 분리: `lint`(black+ruff) / `typecheck`(mypy) / `complexity`(radon/xenon) / `docstring`(interrogate)
  - pre-commit과 CI: 동일 명령(`ruff check` non-fix 모드 사용), 동일 도구 버전 핀
- **산출물**:
  - `_workspace/04b_quality_gate.md` (본 문서)
  - `_workspace/02_pipeline_config/pyproject.toml.patch`
  - `_workspace/02_pipeline_config/.pre-commit-config.yaml.patch`
  - `_workspace/02_pipeline_config/.github/workflows/ci-quality-patch.yml`

---

## 1. 현황 진단

### 1.1 pyproject 설정 점검

| 항목 | 현재 | 평가 | 강화 |
|------|------|------|------|
| `[tool.black]` line-length=88, target=py311, extend-exclude=`projects/benchmarks/scripts` | OK | 정합 | 유지 |
| `[tool.ruff]` line-length=88, target=py311, extend-exclude 동일 | OK | 정합 | 유지 |
| `[tool.ruff.lint] select` = `E,W,F,I,B,UP,S,ANN` | 부분 | 핵심은 있으나 D/T20/PT/PTH/RUF/ASYNC/C90/TID/SIM/N/PL 미선택 | **추가 필요** |
| `[tool.ruff.lint] ignore` = `ANN101,ANN102,S101` | OK | 합리적 | `D203,D213` 등 pydocstyle 충돌만 추가 |
| `per-file-ignores` tests/scripts 완화 | OK | 합리적 | tests에 `D,PT004` 일부 완화 추가 |
| `[tool.mypy] strict=true` | OK | 강함 | `disallow_any_explicit/decorated/unimported` 명시 추가 |
| `[tool.mypy] python_version=3.12` | ⚠️ | black/ruff(py311)와 불일치 | **통일 필요** (runtime은 3.11+) |
| `[tool.pytest.ini_options]` asyncio_mode=auto | OK | 정합 | `--cov-fail-under` 등 커버리지는 test-engineer 영역 |

### 1.2 ruff 룰셋 갭 (자동 강제 가능 컨벤션 vs 미반영)

| `.claude/rules/python-conventions.md` 규약 | 자동 강제 도구 | 현재 활성 | 갭 |
|---|---|---|---|
| public 함수 타입힌트 필수 | ruff `ANN` + mypy `disallow_untyped_defs` | ✓ ANN, ✓ mypy strict | — |
| `Any` 금지 → Unknown+TypeGuard | mypy `disallow_any_explicit` | ✗ | **추가** |
| Google 스타일 독스트링 (public 필수) | ruff `D` + `pydocstyle.convention=google` | ✗ | **추가** |
| `print()` 금지 → get_logger | ruff `T20` | ✗ | **추가** |
| bare `except:` 금지 | ruff `E722` (E 룰셋 내 포함) | ✓ | — |
| 와일드카드 임포트 금지 | ruff `F403/F405` (F 룰셋 내 포함) | ✓ | — |
| 동기 블로킹 in async (requests/time.sleep) | ruff `ASYNC` | ✗ | **추가** |
| f-string 권장, `%` 포맷 금지 | ruff `UP031,UP032` (UP 룰셋 내) | ✓ | — |
| 큰따옴표 통일 | black 기본 | ✓ | — |
| 4칸 들여쓰기 | black | ✓ | — |
| pytest 패턴 (PT) | ruff `PT` | ✗ | **추가** |
| 명명 규칙 (snake/Pascal/UPPER, 약어 대문자) | ruff `N` (pep8-naming) | ✗ | **추가** (예외: `SOC*`, `UAV*`는 ignore-names) |
| 순환 복잡도 ≤ 10 | ruff `C90` (mccabe) | ✗ | **추가** |
| Tidy imports (단일 모듈 임포트 형식) | ruff `TID` | ✗ | **추가** |
| pathlib 우선 (`os.path` 회피) | ruff `PTH` | ✗ | **추가** |

### 1.3 .pre-commit-config.yaml 정합성

| 훅 | CI 대응 | 명령 | 일치 | 비고 |
|----|---------|------|------|------|
| black v24.4.2 | CI `black --check .` | 동일 동작(pre-commit은 자동 포맷) | ⚠️ | 버전 핀 pyproject(`black>=24.0.0`)와 충돌 가능. pre-commit이 24.4.2 고정. **CI도 동일 버전 핀 권장**. |
| ruff v0.4.9 | CI `ruff check .` | pre-commit은 `--fix`, CI는 비-fix | ⚠️ | 드리프트 위험 — pre-commit에서 자동수정되면 CI는 통과. 의도된 동작이나 **`ruff-format` 훅 사용 시 CI에 `ruff format --check` 추가 필요** |
| ruff-format | CI 미존재 | — | ✗ | **CI에 `ruff format --check .` 추가 필요** 또는 black과 중복이면 ruff-format 제거 |
| mypy v1.10.0 | CI `mypy .` | 동일 | ✓ | 단, mypy `additional_dependencies` 누락(`pydantic-settings`만 있음) — `compliance-trestle`, `jsonschema`, `langchain*`, `httpx` 추가 필요 |
| gitleaks v8.18.4 | CI 미존재 | — | ✗ | security-scanner 영역 (별도 `secret-scan` 잡 추가) |
| interrogate/radon | 둘 다 없음 | — | ✗ | **신규 추가** |

### 1.4 종합 진단

- **차단형 게이트로 부족**: 독스트링(D), `print()`(T20), 복잡도(C90), pytest 패턴(PT), pathlib(PTH), async 블로킹(ASYNC), 명명(N) — 모두 코드리뷰 의존 → 자동화 가능
- **mypy 강화 여지**: `disallow_any_explicit` 미명시 → `Any` 사용이 명시적으로 적힌 경우 통과해버림
- **버전 드리프트 위험**: pyproject dev 의존성은 `>=`로 느슨, pre-commit은 정확 핀 — **CI도 정확 핀 권장**(reproducibility)
- **잡 구조**: lint 한 잡에 black+ruff+mypy 합쳐있어 실패 시 어떤 게이트인지 분간 어려움 → **분리 권장**

---

## 2. 강화안 (pyproject + ci.yml 패치)

### 2.1 pyproject.toml — `[tool.ruff.lint]` 강화

추가 select 룰셋(모두 차단형):

```toml
[tool.ruff.lint]
select = [
    "E",     # pycodestyle 오류 (E722 bare except 포함)
    "W",     # pycodestyle 경고
    "F",     # pyflakes (F403/F405 wildcard import 포함)
    "I",     # isort (임포트 순서)
    "N",     # pep8-naming (snake/Pascal/UPPER)
    "D",     # pydocstyle (Google 독스트링)
    "B",     # flake8-bugbear (잠재적 버그)
    "UP",    # pyupgrade (구식 문법, %-format 금지)
    "S",     # flake8-bandit (보안)
    "ANN",   # flake8-annotations (타입힌트)
    "T20",   # flake8-print (print 금지)
    "PT",    # flake8-pytest-style
    "PTH",   # flake8-use-pathlib (os.path 회피)
    "ASYNC", # flake8-async (async 블로킹 호출)
    "SIM",   # flake8-simplify
    "TID",   # flake8-tidy-imports
    "RUF",   # ruff 전용 규칙
    "C90",   # mccabe 복잡도
    "PL",    # pylint subset (PLR, PLW, PLE)
]
ignore = [
    "ANN101", # self 타입힌트 생략 허용
    "ANN102", # cls 타입힌트 생략 허용
    "S101",   # assert 허용 (테스트 코드)
    "D203",   # 1 blank line before class docstring (D211과 충돌)
    "D213",   # Multi-line docstring summary should start at the second line (D212와 충돌, Google은 D212 채택)
    "PLR0913", # 너무 많은 인자 — Agent 생성자에 정당화 가능
]

[tool.ruff.lint.mccabe]
max-complexity = 10  # 함수당 순환 복잡도 상한

[tool.ruff.lint.pydocstyle]
convention = "google"

[tool.ruff.lint.flake8-tidy-imports]
ban-relative-imports = "all"

[tool.ruff.lint.pep8-naming]
# 약어 클래스 대문자 유지 (SOCAgent, UAVTriageAgent)
extend-ignore-names = ["SOC*", "UAV*", "TI*", "ML*", "AI*", "RAG*", "ATT*"]
classmethod-decorators = ["classmethod", "pydantic.validator", "pydantic.root_validator"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["ANN", "S", "D", "PT004", "PLR2004"]
"scripts/**" = ["ANN", "S", "D", "T20"]
"compliance/**" = ["S"]
"app/**" = ["D"]      # app 진입점은 docstring 면제 (필요 시 조정)
"**/__init__.py" = ["D104"]  # 패키지 docstring 미강제(필요 시)
```

### 2.2 pyproject.toml — `[tool.mypy]` 강화

```toml
[tool.mypy]
python_version = "3.11"          # ⚠️ 변경: black/ruff(py311)와 통일. 런타임 3.12 사용 시 별도 환경에서 검사
strict = true
exclude = "^(projects|benchmarks|scripts)/"

# strict 명시 + 추가 강화 (strict에 포함되지 않는 항목)
disallow_any_generics = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_return_any = true

# 추가 강화 — `.claude/rules/python-conventions.md` "Any 금지" 자동 강제
disallow_any_explicit = true       # `: Any` 명시적 사용 금지
disallow_any_decorated = true      # 데코레이트된 함수의 Any 금지
disallow_any_unimported = true     # 임포트 실패한 타입의 암묵적 Any 금지
warn_unreachable = true
strict_equality = true
extra_checks = true
```

> **python_version 통일 결정**: 프로젝트 `requires-python>=3.11`, black/ruff는 `py311`. mypy만 `3.12`이면 타깃 불일치. 권고: **mypy를 3.11로 통일** (런타임 3.12는 backward compatible). 단, 현재 mypy 주석에 "numpy 등 전이 의존 스텁이 3.12 전용 type 문법"이라 명시되어 있으므로 **사용자 결정 필요** — 본 문서는 두 옵션 제시.

### 2.3 pyproject.toml — 신규 도구 섹션

```toml
# ─── interrogate (독스트링 커버리지) ───
[tool.interrogate]
ignore-init-method = true
ignore-init-module = false
ignore-magic = false
ignore-semiprivate = false
ignore-private = false
ignore-property-decorators = false
ignore-module = false
ignore-nested-functions = false
ignore-nested-classes = false
ignore-setters = false
fail-under = 80           # public symbols 80% 강제
exclude = ["projects", "benchmarks", "scripts", "tests"]
verbose = 1
quiet = false
color = true

# ─── radon/xenon (복잡도 게이트 보조) ───
# ruff C90이 1차, xenon이 2차 — 함수 등급 ≤ B, 모듈 평균 ≤ A 강제
# CLI: xenon --max-absolute B --max-modules A --max-average A . --exclude projects,benchmarks,scripts
```

### 2.4 신규 dev 의존성

```toml
[project.optional-dependencies]
dev = [
    "black>=24.0.0,<25",
    "ruff>=0.5.0,<0.6",        # 0.5에서 ASYNC, PTH 등 안정화
    "mypy>=1.10.0,<2",
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=5.0.0",       # test-engineer 영역과 공유
    "pre-commit>=3.7.0",
    "interrogate>=1.7.0",      # 독스트링 커버리지
    "xenon>=0.9.1",            # 복잡도 게이트 보조
    "pollack-ai[sim]",
]
```

> 버전 상한 핀 권장 (방산: reproducibility). 현재 `>=`만 사용 — 강화 시 점진 채택.

---

## 3. CI 잡 강화 (.github/workflows/ci-quality-patch.yml)

기존 `ci.yml`의 `lint` 잡을 분해/강화한 패치. **추가/대체 워크플로**로 제공.

### 3.1 잡 분리 구조

```
lint        — black --check + ruff check + ruff format --check
typecheck   — mypy
complexity  — xenon (ruff C90 보조)
docstring   — interrogate (커버리지 ≥80%)
convention  — grep 게이트 (print/bare except 잔존 확인, ruff와 중복방어)
```

### 3.2 ci-quality-patch.yml 본문

`_workspace/02_pipeline_config/.github/workflows/ci-quality-patch.yml`에 별도 저장. 본 문서 §7 참조.

핵심 결정:
- 모든 잡 `runs-on: ubuntu-latest`, 동일 파이썬 3.11 cache=pip
- `ruff check . --output-format=github` → PR 어노테이션 자동
- `mypy . --no-incremental` → reproducible
- `xenon --max-absolute B --max-modules A --max-average A .`
- `interrogate -c pyproject.toml .`
- 잡 실패 시 **차단** (continue-on-error 사용 금지)

### 3.3 PR 코드리뷰 자동화

ruff `--output-format=github`은 GitHub Actions 어노테이션을 자동 생성한다. 추가로 `reviewdog/action-suggester`는 선택 사항(현재 GHAS만 사용 중이므로 우선 ruff 어노테이션 채택). 향후:

```yaml
- name: ruff (reviewdog 어노테이션)
  uses: reviewdog/action-ruff@<SHA>   # SHA 핀 — security-scanner와 협의
  with:
    reporter: github-pr-review
    fail_on_error: true
    level: error
```

---

## 4. pre-commit 정합성 (.pre-commit-config.yaml.patch)

### 4.1 변경 요지

| 항목 | 현재 | 변경 |
|------|------|------|
| black rev | `24.4.2` | 유지 (CI도 동일 버전으로 핀) |
| ruff rev | `v0.4.9` | **`v0.5.7`** (ASYNC/PTH 안정화) |
| ruff hook args | `--fix` | `--fix --exit-non-zero-on-fix` 추가 — 자동수정 발생 시에도 실패로 처리해 CI와 정합 |
| ruff-format hook | 활성 | 활성 유지, **CI에 `ruff format --check` 추가** |
| mypy rev | `v1.10.0` | 유지 |
| mypy additional_dependencies | pydantic, pydantic-settings, types-httpx | **추가**: `compliance-trestle`, `jsonschema`, `langchain-core`, `langgraph`, `httpx` |
| interrogate hook | 없음 | **추가** (독스트링 커버리지) |
| xenon hook | 없음 | 선택 (CI에만 있어도 됨, 로컬 부하 고려) |

### 4.2 핵심 원칙

- pre-commit은 **자동 수정**, CI는 **검증** — `--exit-non-zero-on-fix`로 CI 미통과를 로컬에서 사전 차단
- 도구 버전은 pre-commit이 SSOT 역할 (정확 핀), pyproject dev는 범위 핀
- 신규 룰셋(D, T20, PT 등) 도입 시 **점진적 적용**: 초기 1주는 `--statistics`로 위반 카운트 후 차단

---

## 5. PR 코드리뷰 자동화 (게이트 매트릭스)

### 5.1 자동 강제 (도구로 차단)

| 위반 | 도구·룰 | 잡 | 차단/경고 |
|------|--------|-----|-----------|
| 파일 포맷 불일치 (88자/들여쓰기/큰따옴표) | black `--check` | lint | **차단** |
| 임포트 순서 위반 | ruff `I` (isort) | lint | **차단** |
| 와일드카드 임포트 | ruff `F403/F405` | lint | **차단** |
| `print()` 사용 | ruff `T20` | lint | **차단** |
| bare `except:` | ruff `E722` | lint | **차단** |
| 명명 규칙 위반 (snake/Pascal/UPPER) | ruff `N` + extend-ignore (SOC*, UAV*) | lint | **차단** |
| 타입힌트 누락 (public) | ruff `ANN` + mypy `disallow_untyped_defs` | lint+typecheck | **차단** |
| `Any` 명시적 사용 | mypy `disallow_any_explicit` | typecheck | **차단** |
| 독스트링 누락 (Google) | ruff `D` (convention=google) | lint | **차단** |
| 독스트링 커버리지 < 80% | interrogate | docstring | **차단** |
| 복잡도 > 10 | ruff `C90` + xenon B | lint+complexity | **차단** |
| async 함수 내 동기 블로킹 (requests/time.sleep) | ruff `ASYNC` | lint | **차단** |
| 보안 위반 (subprocess shell=True 등) | ruff `S` (bandit) | lint | **차단** |
| `os.path` 사용 (pathlib 권고) | ruff `PTH` | lint | **차단** |
| pytest 안티패턴 (fixture 인자 누락 등) | ruff `PT` | lint | **차단** |

### 5.2 파일명 규약 — grep 게이트 (도구 미커버)

`{role}_agent.py`, `{service}_tool.py` 강제는 ruff로는 불가. **간이 grep 게이트**:

```yaml
convention:
  name: Naming Convention Check
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@<SHA>
    - name: agents/ 파일명 규약
      run: |
        bad=$(find agents -type f -name "*.py" ! -name "__init__.py" ! -name "base.py" ! -name "*_agent.py" || true)
        if [ -n "$bad" ]; then
          echo "::error::agents/ 하위는 {role}_agent.py 형식이어야 합니다: $bad"
          exit 1
        fi
    - name: tools/ 파일명 규약
      run: |
        bad=$(find tools -type f -name "*.py" ! -name "__init__.py" ! -name "base.py" ! -name "*_tool.py" || true)
        if [ -n "$bad" ]; then
          echo "::error::tools/ 하위는 {service}_tool.py 형식이어야 합니다: $bad"
          exit 1
        fi
    - name: print() 잔존 확인 (이중 방어)
      run: |
        # ruff T20과 중복이지만, 누락된 디렉토리를 잡기 위한 2차 방어
        bad=$(grep -rEn --include="*.py" "^[[:space:]]*print\(" agents core tools utils app || true)
        if [ -n "$bad" ]; then
          echo "::error::print() 사용 금지 — get_logger() 사용:"
          echo "$bad"
          exit 1
        fi
```

### 5.3 사람 리뷰 영역 (도구 미커버)

- 아키텍처 정합성 (BaseSOCAgent / BaseTool 상속, 디렉토리 규칙)
- 커스텀 예외 `SOCPlatformError` 하위 정의 여부
- LLM 호출 `try/except` 래핑 여부
- 민감 데이터 로깅 마스킹
- 미검증 외부 입력(Sentinel/TI 응답) 파싱·검증

→ **CODEOWNERS 지정** 및 PR 템플릿에 체크박스 추가 권장(pipeline-reviewer 영역).

---

## 6. 수용 기준 (게이트 통과 기준)

| 게이트 | 명령 | 통과 조건 |
|--------|------|----------|
| black | `black --check .` | exit 0 (수정 사항 0) |
| ruff lint | `ruff check . --output-format=github` | violation 0 |
| ruff format | `ruff format --check .` | 수정 사항 0 |
| mypy | `mypy .` | error 0 |
| interrogate | `interrogate -c pyproject.toml .` | 독스트링 커버리지 ≥ 80% (public) |
| xenon | `xenon --max-absolute B --max-modules A --max-average A .` | 위반 0 |
| convention grep | (위 §5.2) | 위반 0 |

**diff coverage(테스트)**는 test-engineer 영역이며 본 게이트 범위에서 제외.

### 6.1 점진 적용 로드맵

| 단계 | 기간 | 새 룰 모드 |
|------|------|-----------|
| 1주차 | 도입 직후 | 신규 D/T20/PT/PTH/ASYNC/C90 — **경고**(soft, `--statistics`만) |
| 2-3주차 | 위반 해소 PR | 신규 룰 **차단**(hard) 전환 |
| 4주차 | 안정화 | interrogate `fail-under=80` 차단, xenon 차단 |

> 방산 컨텍스트상 최종 목표는 **모두 차단**. 1주 경고 기간만 부여.

---

## 7. 산출 패치 파일

### 7.1 `_workspace/02_pipeline_config/pyproject.toml.patch`

본 문서 §2의 변경사항을 통합 패치 형태로 제공. 별도 파일에 저장.

### 7.2 `_workspace/02_pipeline_config/.pre-commit-config.yaml.patch`

본 문서 §4의 변경사항을 통합 패치 형태로 제공. 별도 파일에 저장.

### 7.3 `_workspace/02_pipeline_config/.github/workflows/ci-quality-patch.yml`

신규 워크플로 또는 기존 ci.yml에 머지할 잡 정의. 별도 파일에 저장.

---

## 8. 팀 협업 포인트

### 8.1 test-engineer 와 협업

1. **커버리지 게이트 분리**: 본 문서는 lint/type만, 커버리지(`--cov-fail-under=80`, diff-cover 90%)는 test-engineer가 `_workspace/04c_test_gate.md`에서 정의 → CI에서는 `test` 잡 내부에서 일원화. **pytest-cov 의존성은 본 문서에서 dev extras에 추가**(§2.4).
2. **interrogate vs pytest doctest**: 본 문서는 interrogate로 docstring 커버리지를 측정, test-engineer는 pytest로 doctest 실행 여부 결정 → 명령 중복 없음.

### 8.2 security-scanner 와 협업

1. **ruff `S`(bandit) vs Semgrep/CodeQL**: ruff S는 syntactic 1차 방어, Semgrep/CodeQL은 데이터 흐름 2차 방어 → **중복 허용**(각 게이트가 다른 범주). 단, `S101 assert`는 ruff에서 제외(테스트 허용).
2. **Gitleaks/Trivy/Syft는 보안 게이트**: 본 품질 게이트에서 제외.
3. **action SHA 핀**: 본 문서 워크플로의 `actions/checkout@<SHA>` 등도 security-scanner의 SHA 핀 정책 따름.

### 8.3 pipeline-designer 와 협업

- pipeline-designer 설계 §5.1 `lint` 잡을 **분해**(lint/typecheck/complexity/docstring/convention 5개) — pipeline-reviewer가 토폴로지 정합성 점검 필요.
- CI 총 소요시간: lint(2분) + typecheck(3분) + complexity(1분) + docstring(1분) + convention(30초) — 병렬 실행 시 최대 **3분** (기존 단일 lint 5분 대비 단축).

### 8.4 pipeline-reviewer 점검 항목

1. **python_version 통일 결정**: mypy 3.12 → 3.11 통일이 numpy 등 전이 스텁과 충돌하지 않는지 확인 필요(현재 주석에 충돌 가능성 명시). 결정에 따라 본 패치 수정.
2. **신규 룰 도입 일정**: §6.1 점진 적용 로드맵의 1주 경고 기간이 운영 가능한지(방산 보안 정책상 즉시 차단 요구 있는지).
3. **interrogate fail-under=80**: 현재 코드베이스 실제 커버리지를 측정해 80%가 합리적인지 검증(낮으면 60→70→80 단계 상향).

---

## 9. 발견 사항 (현행 코드베이스 빠른 스캔 기반)

### 9.1 Quality Gate 관점 즉시 강화 항목

🔴 **필수**
- `[tool.mypy] python_version=3.12` vs black/ruff `py311` 불일치 → 통일 결정 필요(주석 근거 검토 후).
- ruff에 `D, T20, ASYNC, C90` 미선택 → `.claude/rules/python-conventions.md`의 핵심 규약(`print` 금지, 독스트링, async 블로킹, 복잡도) 자동 강제 부재.
- mypy `disallow_any_explicit` 미명시 → `: Any` 사용이 strict 모드에서도 통과 가능.

🟡 **권장**
- pre-commit `ruff --fix` vs CI `ruff check` 드리프트 → `--exit-non-zero-on-fix` 추가로 정합.
- mypy `additional_dependencies`에 `langchain*`, `httpx`, `jsonschema`, `compliance-trestle` 미추가 → 로컬 pre-commit 타입 검사 누락 가능.
- dev extras 버전이 `>=`만 사용 → 방산 reproducibility 관점에서 상한 핀(`<25` 등) 권장.

🟢 **참고**
- `ruff-format` 사용 중인데 `black`과 중복 — 둘 중 하나로 통일(현행 black 유지가 무난, ruff-format은 제거 가능). 단, 둘 다 두면 ruff-format이 black 출력과 호환되어 무해.

---

## 10. 참조

- `.claude/rules/python-conventions.md` — 본 게이트의 강제 원천
- `CLAUDE.md` — 보안 규칙 / 명명 / 자동화 명령
- `_workspace/01_pipeline_design.md` §5.1 — CI 게이트 매트릭스 (lint 잡 위치)
- `python-quality-gates` 스킬 — 도구·임계값 표준
