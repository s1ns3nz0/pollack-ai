# S8 온보드 인식 AI 적대공격 — 라이브 폐루프 데모 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** S1(GNSS 스푸핑) 폐루프와 대칭되게, S8(온보드 EO/IR 표적인식 AI 적대공격)을 레드 주입→BLUE SOC 탐지→드론 가시 반응(자율교전 차단 hold→보수적 RTB)으로 구성해 녹화 가능하게 한다.

**Architecture:** SITL엔 인식 모델이 없으므로 **합성 EO/IR 인식 추론 스트림**이 공격면이 된다. RED 인젝터가 정상→적대(EO/IR 클래스 불일치 + 신뢰도 gap≥0.15) 레코드를 perception NDJSON 스트림 파일에 append하고, BLUE 러너가 그 파일을 tail해 `OnboardAIDetector`로 탐지한다. 탐지 시 기존 `SimBridge`에서 추출한 `run_alert(alert)`로 6-에이전트 SOC+RAG+LLM을 재사용하고, `MavlinkActuator`로 실 SITL 드론을 LOITER hold 후 RTB 시킨다.

**Tech Stack:** Python 3.11, pydantic v2, pymavlink, asyncio, pytest(+pytest-asyncio), 기존 `sim_bridge`/`agents`(LangGraph) 파이프라인.

**전제(모든 명령 공통):**
```bash
cd /gpfs/home/jm00055/pollack-ai && source .venv/bin/activate
```

**보존 규칙:** 작업 트리의 미커밋 변경(`agents/`·`core/`·`sim_bridge/detector.py` auto-rearm·`tests/__tests__/test_sim_bridge.py`)은 **건드리지 말고 그 위에 추가만** 한다. `detector.py`는 기존 `GpsSpoofDetector` 아래에 새 클래스를 덧붙인다.

---

## File Structure

| 파일 | 책임 |
|---|---|
| `sim_bridge/models.py` (수정) | `PerceptionRecord` 추가 — EO/IR 추론 NDJSON 한 줄 |
| `sim_bridge/perception_synth.py` (신규) | 정상/적대 인식 레코드 생성기(RED 공격 콘텐츠) |
| `sim_bridge/detector.py` (수정) | `OnboardAIDetector` + `_build_onboard_alert` + `_S8_PLAYBOOK` 추가 |
| `sim_bridge/bridge.py` (수정) | `run_alert(alert)` 추출(탐지/SOC 분리) — 가산적 |
| `sim_bridge/actuator.py` (수정) | `OnboardActuator` Protocol + `MavlinkActuator.send_loiter` + `hold_then_rtb` 추가 |
| `scripts/sim_inject_onboard_evade.py` (신규) | RED: 적대 인식 스트림 방출 |
| `scripts/sim_live_bridge_onboard.py` (신규) | BLUE: 스트림 tail → 탐지 → 대시보드 → HITL → hold→RTB |
| `tests/__tests__/test_sim_bridge.py` (수정) | S8 탐지/브리지/액추에이터 테스트 추가 |
| `docs/demo-runbook-s8.md` (신규) | S8 시연 녹화 런북 |

---

## Task 1: PerceptionRecord 모델

**Files:**
- Modify: `sim_bridge/models.py`
- Test: `tests/__tests__/test_sim_bridge.py`

- [ ] **Step 1: 실패 테스트 작성** — `tests/__tests__/test_sim_bridge.py` 임포트 블록과 클래스에 추가.

임포트 블록(파일 상단, 기존 임포트 아래)에 추가:
```python
from sim_bridge.models import PerceptionRecord
```

`class TestTelemetryRecord:` 바로 아래(새 클래스)로 추가:
```python
class TestPerceptionRecord:
    """인식 추론 NDJSON 별칭 파싱."""

    def test_alias_parsing(self) -> None:
        """EoClass/IrConfidence 등 별칭 키가 필드로 매핑된다."""
        r = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "bird",
                "EoConfidence": 0.88,
                "IrConfidence": 0.42,
            }
        )
        assert r.msg_type == "PERCEPTION_INFERENCE"
        assert r.eo_class == "vehicle"
        assert r.ir_class == "bird"
        assert r.eo_conf == 0.88
        assert r.ir_conf == 0.42
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestPerceptionRecord -v`
Expected: FAIL — `ImportError: cannot import name 'PerceptionRecord'`

- [ ] **Step 3: 최소 구현** — `sim_bridge/models.py` 끝에 클래스 추가(기존 `TelemetryRecord` 아래).

```python
class PerceptionRecord(BaseModel):
    """온보드 EO/IR 표적인식 추론 NDJSON 한 줄(S8 탐지 관련 필드).

    SITL 엔 실제 인식 모델이 없어 합성 스트림으로 대체한다. 필드명은 perception-tap
    NDJSON 스키마(가상)와 동일하게 별칭으로 매핑한다.
    """

    model_config = ConfigDict(extra="ignore")

    time_generated: str = Field(default="", alias="TimeGenerated")
    uav_id: str = Field(default="UNKNOWN", alias="UAVId")
    msg_type: str = Field(default="", alias="MsgType")
    target_id: str = Field(default="", alias="TargetId")

    # 다중센서 융합 — EO(가시) vs IR(열) 표적 클래스/신뢰도
    eo_class: str | None = Field(default=None, alias="EoClass")
    ir_class: str | None = Field(default=None, alias="IrClass")
    eo_conf: float | None = Field(default=None, alias="EoConfidence")
    ir_conf: float | None = Field(default=None, alias="IrConfidence")

    @classmethod
    def from_ndjson(cls, data: dict[str, object]) -> PerceptionRecord:
        """NDJSON dict(원본 키) → PerceptionRecord."""
        return cls.model_validate(data)
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestPerceptionRecord -v`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add sim_bridge/models.py tests/__tests__/test_sim_bridge.py
git commit -m "feat: PerceptionRecord 모델(S8 온보드 EO/IR 인식 추론 레코드)"
```

---

## Task 2: perception_synth — 정상/적대 인식 스트림 생성기

**Files:**
- Create: `sim_bridge/perception_synth.py`
- Test: `tests/__tests__/test_sim_bridge.py`

- [ ] **Step 1: 실패 테스트 작성** — 임포트 블록에 추가:
```python
from sim_bridge.perception_synth import (
    adversarial_perception,
    benign_perception,
    synth_perception_records,
)
```

`TestPerceptionRecord` 아래에 추가:
```python
class TestPerceptionSynth:
    """합성 인식 스트림(정상/적대) 값 검증."""

    def test_benign_classes_agree_small_gap(self) -> None:
        """정상: EO/IR 클래스 일치 + 신뢰도 gap 작음(<0.15)."""
        b = benign_perception()
        assert b["EoClass"] == b["IrClass"]
        assert abs(float(b["EoConfidence"]) - float(b["IrConfidence"])) < 0.15

    def test_adversarial_mismatch_and_large_gap(self) -> None:
        """적대: EO/IR 클래스 불일치 + 신뢰도 gap≥0.15."""
        a = adversarial_perception()
        assert a["EoClass"] != a["IrClass"]
        assert abs(float(a["EoConfidence"]) - float(a["IrConfidence"])) >= 0.15

    def test_synth_records_benign_then_adversarial(self) -> None:
        """정상 N건 → 적대 2건(확정 스트릭) 순서."""
        recs = synth_perception_records(benign_n=4)
        assert len(recs) == 6
        assert recs[0].eo_class == recs[0].ir_class  # 정상
        assert recs[-1].eo_class != recs[-1].ir_class  # 적대
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestPerceptionSynth -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sim_bridge.perception_synth'`

- [ ] **Step 3: 최소 구현** — `sim_bridge/perception_synth.py` 생성.

```python
"""합성 온보드 EO/IR 인식 추론 스트림 생성기(S8 — 인식 모델 없이 브리지 검증).

정상 정찰 중 EO(가시)/IR(열) 센서가 동일 표적을 일치되게 고신뢰로 인식하다가,
적대적 패치/디코이/dazzling 주입 구간에서 EO/IR 표적 클래스 불일치 + 신뢰도
이상분포(gap≥0.15)를 만든다. 출력 dict 는 perception NDJSON 키와 동일하므로 실
인식-탭 스트림으로 그대로 교체 가능하다.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sim_bridge.models import PerceptionRecord


def benign_perception(
    uav_id: str = "MPD-001", target_id: str = "TGT-01"
) -> dict[str, object]:
    """정상 인식 — EO/IR 동일 클래스 + 단봉 고신뢰(불일치/이상분포 없음)."""
    return {
        "TimeGenerated": "2026-06-25T00:00:00Z",
        "UAVId": uav_id,
        "MsgType": "PERCEPTION_INFERENCE",
        "TargetId": target_id,
        "EoClass": "vehicle",
        "IrClass": "vehicle",
        "EoConfidence": 0.93,
        "IrConfidence": 0.90,
    }


def adversarial_perception(
    uav_id: str = "MPD-001", target_id: str = "TGT-01"
) -> dict[str, object]:
    """적대 인식 — EO=vehicle / IR=bird 불일치 + 신뢰도 gap(0.46)."""
    return {
        "TimeGenerated": "2026-06-25T00:00:10Z",
        "UAVId": uav_id,
        "MsgType": "PERCEPTION_INFERENCE",
        "TargetId": target_id,
        "EoClass": "vehicle",
        "IrClass": "bird",
        "EoConfidence": 0.88,
        "IrConfidence": 0.42,
    }


def synth_perception_records(
    uav_id: str = "MPD-001", benign_n: int = 5
) -> list[PerceptionRecord]:
    """정상 N건 → 적대 2건(확정 스트릭 충족) 시퀀스."""
    raw: list[dict[str, object]] = [benign_perception(uav_id) for _ in range(benign_n)]
    raw.append(adversarial_perception(uav_id))
    raw.append(adversarial_perception(uav_id))
    return [PerceptionRecord.from_ndjson(r) for r in raw]


async def synth_perception_stream(
    uav_id: str = "MPD-001", benign_n: int = 5
) -> AsyncIterator[PerceptionRecord]:
    """비동기 스트림 버전(브리지 검증용)."""
    for record in synth_perception_records(uav_id, benign_n):
        yield record
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestPerceptionSynth -v`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add sim_bridge/perception_synth.py tests/__tests__/test_sim_bridge.py
git commit -m "feat: 합성 EO/IR 인식 스트림 생성기(S8 RED 공격 콘텐츠)"
```

---

## Task 3: OnboardAIDetector — 센서 불일치 + 신뢰도 이상분포 탐지

**Files:**
- Modify: `sim_bridge/detector.py`
- Test: `tests/__tests__/test_sim_bridge.py`

- [ ] **Step 1: 실패 테스트 작성** — 임포트 블록에 추가:
```python
from sim_bridge.detector import OnboardAIDetector
```

`TestGpsSpoofDetector` 아래(새 클래스)로 추가:
```python
class TestOnboardAIDetector:
    """S8 온보드 인식 적대공격 탐지기."""

    def _benign(self) -> PerceptionRecord:
        return PerceptionRecord.from_ndjson(benign_perception())

    def _adversarial(self) -> PerceptionRecord:
        return PerceptionRecord.from_ndjson(adversarial_perception())

    def test_benign_no_alert(self) -> None:
        """정상 인식(클래스 일치·gap 작음)엔 경보 없음."""
        det = OnboardAIDetector()
        for _ in range(5):
            assert det.observe(self._benign()) is None

    def test_adversarial_fires_alert(self) -> None:
        """불일치+신뢰도 이상분포가 확정 스트릭만큼 지속되면 S8 경보."""
        det = OnboardAIDetector(confirm=2)
        det.observe(self._benign())
        first = det.observe(self._adversarial())  # streak 1 — 아직
        second = det.observe(self._adversarial())  # streak 2 — 발화
        assert first is None
        assert second is not None
        assert second.scenario_id == "AI-ONBOARD-EVADE-008"
        assert second.severity_baseline == Severity.MEDIUM
        assert second.asset_id == "PAYLOAD_EOIR"
        assert any("불일치" in s for s in second.signals)

    def test_mismatch_only_fires(self) -> None:
        """클래스 불일치만 있어도(신뢰도 gap 작아도) 지속 시 발화."""
        det = OnboardAIDetector(confirm=1)
        rec = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "bird",
                "EoConfidence": 0.80,
                "IrConfidence": 0.78,  # gap 0.02 < 0.15
            }
        )
        alert = det.observe(rec)
        assert alert is not None
        assert any("불일치" in s for s in alert.signals)

    def test_confidence_only_fires(self) -> None:
        """클래스 일치하지만 신뢰도 이상분포(gap≥0.15)만으로도 발화."""
        det = OnboardAIDetector(confirm=1)
        rec = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "vehicle",
                "EoConfidence": 0.90,
                "IrConfidence": 0.40,  # gap 0.50
            }
        )
        alert = det.observe(rec)
        assert alert is not None
        assert any("신뢰도" in s for s in alert.signals)

    def test_duplicate_suppressed(self) -> None:
        """동일 사건 중복 발화 억제."""
        det = OnboardAIDetector(confirm=1)
        first = det.observe(self._adversarial())
        second = det.observe(self._adversarial())
        assert first is not None
        assert second is None

    def test_auto_rearm_after_clean(self) -> None:
        """정상 복귀가 이어지면 재무장해 다음 공격을 다시 탐지(재촬영)."""
        det = OnboardAIDetector(confirm=1, rearm_after=3)
        assert det.observe(self._adversarial()) is not None  # 1차
        for _ in range(4):
            det.observe(self._benign())  # 정상 복귀 → 재무장
        assert det.observe(self._adversarial()) is not None  # 2차
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestOnboardAIDetector -v`
Expected: FAIL — `ImportError: cannot import name 'OnboardAIDetector'`

- [ ] **Step 3: 최소 구현** — `sim_bridge/detector.py` 끝(기존 `GpsSpoofDetector` 아래)에 추가.

먼저 파일 상단 임포트에 `PerceptionRecord` 추가(기존 `from sim_bridge.models import TelemetryRecord` 줄을 교체):
```python
from sim_bridge.models import PerceptionRecord, TelemetryRecord
```

파일 끝에 추가:
```python
# S8 시나리오 매핑(고정) — projects/dah2026/scenarios/S8-onboard-ai-evade.yaml
_S8_PLAYBOOK: dict[str, object] = {
    "id": "PB-ONBOARDAI-08",
    "actions": [
        "다중센서 융합 교차검증, 불일치 표적 보류",
        "탐지 신뢰도 이상 시 자율교전 차단 + HITL 표적확인",
        "적대적 견고화(robust) 모델/입력 정규화 런타임 방어",
        "인식 신뢰 불가 시 보수적 RTB",
    ],
    "onboard_defense": [
        "메타 AI 가 주 비전모델 출력 신뢰도·판단 패턴 상시 감시(AI 가 AI 를 감시)",
        "적대 의심 시 경량 백업 비전모델 자동 전환 + 주 모델 격리",
    ],
    "failover": "인식 신뢰 불가 시 자율교전 금지, 보수적 RTB 후 운용자 수동 식별",
    "hitl": "severity=m → 자율교전 차단 후 표적확인",
}


def _build_onboard_alert(uav_id: str, signals: list[str]) -> Alert:
    return Alert(
        id=f"SIM-{uav_id}-ONBOARDAI",
        scenario_id="AI-ONBOARD-EVADE-008",
        title="온보드 표적인식 AI 적대공격 의심 (시뮬 실시간 탐지)",
        asset_id="PAYLOAD_EOIR",
        asset_tier="T2-Important",
        mission_phase="on-station",
        severity_baseline=Severity.MEDIUM,
        signals=signals,
        mitre={"atlas": ["AML.T0015-EvadeMLModel", "AML.T0043-CraftAdversarialData"]},
        expected_detection={"sigma_rule": "onboard_ai_adversarial_evade.yml"},
        defense_playbook=_S8_PLAYBOOK,
        ground_truth=Verdict.TRUE_POSITIVE,
    )


class OnboardAIDetector:
    """다중센서(EO/IR) 표적 불일치 + 탐지 신뢰도 이상분포 결합 S8 탐지기.

    yaml `expected_detection.logic`("센서간 표적 불일치 OR 탐지 신뢰도 이상분포 시
    적대 공격 의심 → HITL 승급")을 런타임 근사한다. 단발 오탐을 막기 위해 신호가
    `confirm` 레코드 연속 지속될 때만 발화하고, `_fired` 로 중복을 억제하며, 정상
    복귀가 `rearm_after` 만큼 이어지면 자동 재무장한다(재촬영 대비 — GpsSpoofDetector
    와 동일 패턴).

    Args:
        conf_gap_threshold: |EO신뢰도 − IR신뢰도| 이상분포 임계(FULL-EXPORT
            MaxConfidenceGap_d=0.15).
        confirm: 발화 전 신호가 연속 지속되어야 하는 레코드 수(트랜지언트 오탐 방지).
        rearm_after: 정상 복귀가 이어지면 재무장할 정상 레코드 수.
    """

    def __init__(
        self,
        conf_gap_threshold: float = 0.15,
        confirm: int = 2,
        rearm_after: int = 10,
    ) -> None:
        self._conf_gap_threshold = conf_gap_threshold
        self._confirm = confirm
        self._rearm_after = rearm_after
        self._signal_streak = 0
        self._clean_streak = 0
        self._fired = False
        self._logger = get_logger("OnboardAIDetector")

    def observe(self, record: PerceptionRecord) -> Alert | None:
        """인식 레코드 한 건으로 상태를 갱신하고, 적대공격이 새로 확정되면 Alert 반환.

        Args:
            record: 온보드 EO/IR 인식 추론 레코드.

        Returns:
            새 탐지면 `Alert`, 아니면 None(중복/미확정 억제).
        """
        signals = self._evaluate(record)
        if not signals:
            self._signal_streak = 0
            self._clean_streak += 1
            if self._fired and self._clean_streak >= self._rearm_after:
                self._fired = False
                self._logger.info("정상 복귀 — 탐지기 재무장")
            return None

        self._clean_streak = 0
        self._signal_streak += 1
        if self._signal_streak < self._confirm:
            return None
        if self._fired:
            return None  # 동일 사건 중복 발화 억제
        self._fired = True
        self._logger.info(
            "온보드 인식 적대공격 탐지: %s | %s", record.uav_id, signals
        )
        return _build_onboard_alert(record.uav_id, signals)

    def _evaluate(self, record: PerceptionRecord) -> list[str]:
        """레코드에서 S8 신호(센서 불일치 / 신뢰도 이상분포)를 추출."""
        signals: list[str] = []
        if (
            record.eo_class is not None
            and record.ir_class is not None
            and record.eo_class != record.ir_class
        ):
            signals.append(
                f"EO/IR 표적 불일치(EO={record.eo_class} vs IR={record.ir_class})"
            )
        if record.eo_conf is not None and record.ir_conf is not None:
            gap = abs(record.eo_conf - record.ir_conf)
            if gap >= self._conf_gap_threshold:
                signals.append(
                    f"탐지 신뢰도 이상분포(gap={gap:.2f}≥{self._conf_gap_threshold})"
                )
        return signals

    def reset(self) -> None:
        """사건 종료 후 재무장."""
        self._signal_streak = 0
        self._clean_streak = 0
        self._fired = False
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestOnboardAIDetector -v`
Expected: PASS (6개)

- [ ] **Step 5: 커밋**

```bash
git add sim_bridge/detector.py tests/__tests__/test_sim_bridge.py
git commit -m "feat: OnboardAIDetector(S8 EO/IR 불일치+신뢰도 이상분포 탐지)"
```

---

## Task 4: SimBridge.run_alert 추출 — 탐지/SOC 분리(재사용 가능)

**Files:**
- Modify: `sim_bridge/bridge.py`
- Test: `tests/__tests__/test_sim_bridge.py`

- [ ] **Step 1: 실패 테스트 작성** — 임포트 블록에 추가:
```python
from sim_bridge.perception_synth import synth_perception_stream
```

`TestSimBridge` 클래스 안, 기존 `test_stream_produces_soc_event` 아래에 추가:
```python
    @pytest.mark.asyncio
    async def test_run_alert_processes_onboard_alert(self) -> None:
        """OnboardAIDetector 탐지 → bridge.run_alert → S8 BridgeEvent(오프라인)."""
        bridge = SimBridge(retriever=None, llm=None)
        det = OnboardAIDetector(confirm=2)
        events = []
        async for rec in synth_perception_stream(benign_n=3):
            alert = det.observe(rec)
            if alert is not None:
                events.append(await bridge.run_alert(alert))
        assert len(events) == 1
        ev = events[0]
        assert ev.alert.scenario_id == "AI-ONBOARD-EVADE-008"
        assert ev.report.severity == Severity.MEDIUM
        assert ev.report.verdict == Verdict.TRUE_POSITIVE
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestSimBridge::test_run_alert_processes_onboard_alert -v`
Expected: FAIL — `AttributeError: 'SimBridge' object has no attribute 'run_alert'`

- [ ] **Step 3: 최소 구현** — `sim_bridge/bridge.py`의 `process` 를 아래처럼 교체(탐지/SOC 분리). 상단 임포트에 `Alert` 가 이미 있으니 확인만(`from core.models import Alert, SOCReport, SOCState`).

> 주의: 동시 peer 작업으로 `process()` 에 `alert = self._tracker.enrich(...)` 줄이 이미 커밋돼 있다. 그 줄은 **S1 경로에 그대로 보존**하고, 그래프 실행+BridgeEvent 조립만 `run_alert` 로 추출한다.

기존(현재 커밋된 상태):
```python
    async def process(self, record: TelemetryRecord) -> BridgeEvent | None:
        """레코드 1건 처리. 탐지 시 SOC 실행 후 BridgeEvent, 아니면 None."""
        alert = self._detector.observe(record)
        if alert is None:
            return None
        alert = self._tracker.enrich(alert, _parse_ts(record.time_generated))
        graph = build_soc_graph(retriever=self._retriever, llm=self._llm)
        state = cast(SOCState, await graph.ainvoke({"alert": alert}))
        inv = state["investigation"]
        return BridgeEvent(
            alert=alert,
            report=state["report"],
            severity_rationale=state["severity_rationale"],
            similar_cases=[c.source for c in inv.similar_cases],
            summary=inv.summary,
            guardrail_flags=state.get("guardrail_flags", []),
        )
```
교체 후:
```python
    async def process(self, record: TelemetryRecord) -> BridgeEvent | None:
        """레코드 1건 처리. 탐지 시 SOC 실행 후 BridgeEvent, 아니면 None."""
        alert = self._detector.observe(record)
        if alert is None:
            return None
        alert = self._tracker.enrich(alert, _parse_ts(record.time_generated))
        return await self.run_alert(alert)

    async def run_alert(self, alert: Alert) -> BridgeEvent:
        """탐지된 Alert 를 6-에이전트 SOC 에 투입하고 BridgeEvent 로 조립한다.

        탐지기 종류(GPS/온보드 인식)와 무관하게 SOC·RAG·LLM 경로를 공유 재사용한다.

        Args:
            alert: 탐지기가 생성한 경보.

        Returns:
            SOC 처리 결과를 담은 `BridgeEvent`.
        """
        graph = build_soc_graph(retriever=self._retriever, llm=self._llm)
        state = cast(SOCState, await graph.ainvoke({"alert": alert}))
        inv = state["investigation"]
        return BridgeEvent(
            alert=alert,
            report=state["report"],
            severity_rationale=state["severity_rationale"],
            similar_cases=[c.source for c in inv.similar_cases],
            summary=inv.summary,
            guardrail_flags=state.get("guardrail_flags", []),
        )
```

- [ ] **Step 4: 통과 확인** — 신규 + 기존 S1 브리지 테스트 모두.

Run: `pytest tests/__tests__/test_sim_bridge.py::TestSimBridge -v`
Expected: PASS (기존 `test_stream_produces_soc_event` + 신규 onboard 테스트)

> 만약 오프라인 검증 경로가 `Verdict.TRUE_POSITIVE` 가 아닌 값을 내면, 이는 plan 가정 위반이므로 멈추고 보고할 것(S1 동일 경로는 TP 를 낸다 — `test_stream_produces_soc_event`).

- [ ] **Step 5: 커밋**

```bash
git add sim_bridge/bridge.py tests/__tests__/test_sim_bridge.py
git commit -m "refactor: SimBridge.run_alert 추출 — 탐지/SOC 분리로 S8 경로 재사용"
```

---

## Task 5: actuator — LOITER hold(자율교전 차단) + hold_then_rtb

**Files:**
- Modify: `sim_bridge/actuator.py`
- Test: `tests/__tests__/test_sim_bridge.py`

- [ ] **Step 1: 실패 테스트 작성** — 임포트 블록에 추가:
```python
from sim_bridge.actuator import hold_then_rtb
```

`TestSimBridge` 아래(파일 끝)에 새 클래스 추가:
```python
class _FakeOnboardActuator:
    """MAVLink 없이 호출 순서만 기록하는 가짜 작동기."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def send_loiter(self, uav_id: str) -> str:
        self.calls.append("loiter")
        return f"LOITER hold 송신({uav_id})"

    def send_rtb(self, uav_id: str) -> str:
        self.calls.append("rtb")
        return f"RTB 송신({uav_id})"


class TestHoldThenRtb:
    """자율교전 차단(hold) → 보수적 RTB 순서 작동."""

    def test_calls_loiter_then_rtb_in_order(self) -> None:
        """hold_then_rtb 는 LOITER 후 RTB 를 순서대로 호출하고 두 메시지를 반환."""
        fake = _FakeOnboardActuator()
        msgs = hold_then_rtb(fake, "MPD-001")
        assert fake.calls == ["loiter", "rtb"]
        assert len(msgs) == 2
        assert "LOITER" in msgs[0]
        assert "RTB" in msgs[1]
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestHoldThenRtb -v`
Expected: FAIL — `ImportError: cannot import name 'hold_then_rtb'`

- [ ] **Step 3: 최소 구현** — `sim_bridge/actuator.py` 수정.

(a) `RtbActuator` Protocol 아래에 새 Protocol 추가:
```python
@runtime_checkable
class OnboardActuator(Protocol):
    """S8 폐루프 작동 인터페이스(자율교전 차단 + 복귀)."""

    def send_loiter(self, uav_id: str) -> str:
        """LOITER hold(자율교전 차단=표적 전진 정지) 명령을 송신한다."""
        ...

    def send_rtb(self, uav_id: str) -> str:
        """RTB(자동 복귀) 명령을 송신한다."""
        ...


def hold_then_rtb(actuator: OnboardActuator, uav_id: str) -> list[str]:
    """자율교전 차단(LOITER hold) 후 보수적 RTB 를 순서대로 작동한다.

    Args:
        actuator: LOITER/RTB 송신 작동기.
        uav_id: 대상 기체 식별자.

    Returns:
        각 단계의 사람이 읽을 결과 문자열 2건([hold, rtb]).

    Raises:
        ActuatorError: 어느 단계든 MAVLink 송신 실패 시.
    """
    return [actuator.send_loiter(uav_id), actuator.send_rtb(uav_id)]
```

(b) `MavlinkActuator` 클래스 안, `send_rtb` 메서드 아래에 `send_loiter` 추가:
```python
    def send_loiter(self, uav_id: str) -> str:
        """기체를 LOITER 모드로 전환해 표적 접근을 멈춘다(자율교전 차단).

        Args:
            uav_id: 대상 기체 식별자(로깅용).

        Returns:
            송신 결과 요약 문자열(대시보드 출력용).

        Raises:
            ActuatorError: HEARTBEAT 수신 실패 또는 MAVLink 송신 오류 시.
        """
        from pymavlink import mavutil  # 지연 임포트(오프라인/테스트 시 불요)

        try:
            conn = mavutil.mavlink_connection(self._connection)
            if conn.wait_heartbeat(timeout=self._heartbeat_timeout) is None:
                raise ActuatorError(
                    f"HEARTBEAT 수신 실패(타임아웃): {self._connection}"
                )
            conn.set_mode("LOITER")
            self._logger.info(
                "LOITER hold 송신: uav=%s via %s (sys=%s)",
                uav_id,
                self._connection,
                conn.target_system,
            )
            return (
                f"MAVLink LOITER(자율교전 차단) 송신 완료 "
                f"(sys={conn.target_system}, via {self._connection})"
            )
        except OSError as e:
            raise ActuatorError(f"LOITER 송신 실패({self._connection}): {e}") from e
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_sim_bridge.py::TestHoldThenRtb -v`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add sim_bridge/actuator.py tests/__tests__/test_sim_bridge.py
git commit -m "feat: actuator LOITER hold(자율교전 차단)+hold_then_rtb 순차 작동"
```

---

## Task 6: RED 인젝터 — sim_inject_onboard_evade.py

**Files:**
- Create: `scripts/sim_inject_onboard_evade.py`

- [ ] **Step 1: 스크립트 작성** — `scripts/sim_inject_onboard_evade.py` 생성.

```python
#!/usr/bin/env python3
"""S8 온보드 인식 AI 적대공격 주입 — 합성 EO/IR 적대 인식 스트림 방출.

SITL 엔 실제 인식 모델이 없으므로, BLUE 러너가 tail 하는 perception NDJSON
스트림 파일에 정상→적대 인식 레코드를 append 한다. 적대 구간은 EO/IR 표적
클래스 불일치 + 신뢰도 이상분포(gap≥0.15)를 만들어 OnboardAIDetector 가
탐지하게 한다. --clear 는 정상 레코드만 흘려 탐지기를 재무장시킨다(재촬영).

스트림 경로: 환경변수 PERCEPTION_STREAM (기본 /tmp/pollack_perception.ndjson).
사전: BLUE `scripts/sim_live_bridge_onboard.py` 가 같은 경로를 tail 중.
실행: python scripts/sim_inject_onboard_evade.py [--clear] [--benign-n 5]
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sim_bridge.perception_synth import (  # noqa: E402
    adversarial_perception,
    benign_perception,
)

STREAM = Path(os.environ.get("PERCEPTION_STREAM", "/tmp/pollack_perception.ndjson"))


def _emit(record: dict[str, object]) -> None:
    """레코드 한 줄을 스트림 파일에 append 하고 즉시 flush."""
    with STREAM.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()


def main() -> None:
    clear = "--clear" in sys.argv
    benign_n = 5
    if "--benign-n" in sys.argv:
        benign_n = int(sys.argv[sys.argv.index("--benign-n") + 1])

    STREAM.parent.mkdir(parents=True, exist_ok=True)
    STREAM.touch(exist_ok=True)
    print(f"[스트림] {STREAM}")

    if clear:
        for _ in range(benign_n):
            _emit(benign_perception())
            time.sleep(0.2)
        print("[복구] 정상 인식 레코드 송출 — 탐지기 재무장.")
        return

    for _ in range(benign_n):
        _emit(benign_perception())
        time.sleep(0.2)
    print("[정상] EO/IR 일치 인식 송출 완료. 적대 주입 시작...")
    for _ in range(4):
        _emit(adversarial_perception())
        time.sleep(0.2)
    print("[주입] 적대 인식(EO=vehicle/IR=bird 불일치 + 신뢰도 gap) 송출 완료.")
    print("       → BLUE OnboardAIDetector 탐지 예상.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 스모크 실행(파일 출력 확인)**

Run:
```bash
PERCEPTION_STREAM=/tmp/s8_smoke.ndjson python scripts/sim_inject_onboard_evade.py --benign-n 2
wc -l /tmp/s8_smoke.ndjson
```
Expected: `6 /tmp/s8_smoke.ndjson` (정상 2 + 적대 4), 출력에 "적대 인식 ... 송출 완료".

- [ ] **Step 3: 정리 + 커밋**

```bash
rm -f /tmp/s8_smoke.ndjson
git add scripts/sim_inject_onboard_evade.py
git commit -m "feat: S8 RED 인젝터(합성 적대 EO/IR 인식 스트림 방출)"
```

---

## Task 7: BLUE 러너 — sim_live_bridge_onboard.py

**Files:**
- Create: `scripts/sim_live_bridge_onboard.py`

- [ ] **Step 1: 스크립트 작성** — `scripts/sim_live_bridge_onboard.py` 생성. (S1 `sim_live_bridge.py` 의 env 로딩·대시보드 패턴을 따르되 인식 스트림 tail + hold→RTB 로 대체.)

```python
#!/usr/bin/env python3
"""S8 온보드 인식 AI 적대공격 → SOC 브리지 (라이브, 인식 스트림).

RED 인젝터가 append 하는 perception NDJSON 스트림 파일을 tail 해 OnboardAIDetector
로 탐지하고, 탐지 시 6-에이전트 SOC(실 RAG/LLM)를 돌려 인식 대시보드를 출력한 뒤
HITL 승인을 받아 실 SITL 드론을 LOITER hold(자율교전 차단) → 보수적 RTB 시킨다.

사전: uav-sim-env 기동 + 드론 이륙(scripts/sim_takeoff.py).
실행: python scripts/sim_live_bridge_onboard.py [--auto] [--no-rtb] [--no-llm]
  --auto    : 운용자 승인 없이 hold→RTB 자동 작동
  --no-rtb  : 폐루프 작동 비활성(대시보드만)
  --no-llm  : LLM 요약 생략(결정론 폴백)
적대 주입(다른 터미널):
  python scripts/sim_inject_onboard_evade.py
"""
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
POC = ROOT / "projects" / "uav_soc_rag_poc"
STREAM = os.environ.get("PERCEPTION_STREAM", "/tmp/pollack_perception.ndjson")


def _load_env() -> None:
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


_load_env()

from core.llm import get_llm_client  # noqa: E402
from sim_bridge.actuator import (  # noqa: E402
    ActuatorError,
    MavlinkActuator,
    OnboardActuator,
    hold_then_rtb,
)
from sim_bridge.bridge import BridgeEvent, SimBridge  # noqa: E402
from sim_bridge.detector import OnboardAIDetector  # noqa: E402
from sim_bridge.models import PerceptionRecord  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


async def _perception_records():
    """perception 스트림 파일(NDJSON)을 tail → PerceptionRecord 스트림."""
    Path(STREAM).parent.mkdir(parents=True, exist_ok=True)
    Path(STREAM).touch(exist_ok=True)
    proc = await asyncio.create_subprocess_exec(
        "tail",
        "-n",
        "0",
        "-F",
        STREAM,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", "ignore").strip()
        if not text.startswith("{"):
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if data.get("MsgType") == "PERCEPTION_INFERENCE":
            yield PerceptionRecord.from_ndjson(data)


async def _actuate_hold_rtb(
    event: BridgeEvent, actuator: OnboardActuator, auto: bool
) -> None:
    """탐지 시 (운용자 승인 후) 자율교전 차단 hold → 보수적 RTB 를 작동한다."""
    if auto:
        print("  [HITL] --auto: 승인 생략, 자율교전 차단→RTB 자동 작동")
    else:
        ans = await asyncio.to_thread(
            input, "  [HITL] 인식 신뢰 불가 — 자율교전 차단 후 RTB 승인? [y/N] "
        )
        if ans.strip().lower() not in ("y", "yes"):
            print("  [HITL] 운용자 거부 — 작동 미실행(권고만 기록)")
            return
    try:
        msgs = await asyncio.to_thread(hold_then_rtb, actuator, event.alert.asset_id)
        for m in msgs:
            print(f"  ✅ 폐루프 작동 : {m}")
        print("     → QGC(noVNC)에서 정지(LOITER) 후 복귀(RTL) 시각화됨")
    except ActuatorError as e:
        print(f"  ⚠️  작동 실패: {e}")


async def main() -> None:
    auto = "--auto" in sys.argv
    no_rtb = "--no-rtb" in sys.argv
    no_llm = "--no-llm" in sys.argv
    actuator: OnboardActuator | None = None if no_rtb else MavlinkActuator()

    print("█" * 66)
    print("  S8 온보드 인식 AI 적대공격  |  라이브 탐지·대응")
    print(f"  perception 스트림: {STREAM}  (tail -F)")
    loop_mode = (
        "비활성(--no-rtb)" if no_rtb else ("자동(--auto)" if auto else "HITL 승인")
    )
    print(f"  폐루프 hold→RTB : {loop_mode}")
    print(f"  LLM 요약        : {'생략(--no-llm)' if no_llm else '실연동'}")
    print("█" * 66)
    print("\n[대기] 정상 인식 모니터링 중... (적대 주입 시 탐지)")

    bridge = SimBridge(
        retriever=RagflowRetrievalTool(),
        llm=None if no_llm else get_llm_client(),
    )
    detector = OnboardAIDetector()
    seen = 0
    async for record in _perception_records():
        seen += 1
        if seen % 20 == 0:
            print(f"  ... 인식 {seen}건 정상 (EO/IR 일치)")
        alert = detector.observe(record)
        if alert is None:
            continue
        event = await bridge.run_alert(alert)
        r = event.report
        print("\n" + "─" * 66)
        print("  🚨 SOC 탐지·대응 (6-에이전트, 실 RAG/LLM) — 온보드 인식 AI")
        print("─" * 66)
        print(f"  경보      : {event.alert.title}")
        print(f"  탐지 신호 : {', '.join(event.alert.signals)}")
        print(f"  심각도    : {r.severity}  ({' '.join(event.severity_rationale)})")
        print(f"  RAG 근거  : {len(event.similar_cases)}건")
        print(f"  LLM 분석  : {event.summary[:160]}...")
        print(f"  판정/대응 : {r.verdict} → {r.action_taken}")
        print("  → 권고    : 센서융합 게이트 + 자율교전 차단 + 보수적 RTB")
        print("─" * 66)
        if actuator is not None:
            await _actuate_hold_rtb(event, actuator, auto)


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: 스모크 실행(임포트/구문 + 오프라인 탐지 경로)** — MAVLink·RAGFlow 없이 임포트만 확인.

Run: `python -c "import ast; ast.parse(open('scripts/sim_live_bridge_onboard.py').read()); print('syntax ok')"`
Expected: `syntax ok`

- [ ] **Step 3: 커밋**

```bash
git add scripts/sim_live_bridge_onboard.py
git commit -m "feat: S8 BLUE 러너(인식 스트림 tail→탐지→HITL→hold→RTB)"
```

---

## Task 8: 런북 + 전체 검증

**Files:**
- Create: `docs/demo-runbook-s8.md`

- [ ] **Step 1: 런북 작성** — `docs/demo-runbook-s8.md` 생성.

````markdown
# S8 시연 녹화 런북 — 온보드 인식 AI 적대공격 (레드/블루 폐루프)

> 스토리: 정상 정찰 중 온보드 EO/IR 표적인식 → 레드가 적대 패치/디코이로 EO/IR
> 표적 불일치+신뢰도 이상분포 유발 → BLUE SOC 실시간 탐지·판정(severity m) →
> HITL 승인 → 자율교전 차단(LOITER hold) → 보수적 RTB(QGC 시각화).

## 0. 사전 준비
```bash
cd ~/pollack-ai && source .venv/bin/activate
# (a) 시뮬 기동 + 드론 이륙 + 정찰 배치 (S1 런북과 동일 인프라 재사용)
python scripts/sim_takeoff.py
# (선택) 전용 GPU Ollama(11435) 워밍업 — docs/demo-runbook.md 1절 참조
```

## 1. 녹화 — 진행
**① BLUE (SOC 방어) 먼저:**
```bash
python scripts/sim_live_bridge_onboard.py        # HITL 승인 버전
#   (무인 자동: --auto / 드론 미연동: --no-rtb / LLM 생략: --no-llm)
```
`[대기] 정상 인식 모니터링 중...` 확인.

**② RED (공격) 다른 터미널:**
```bash
python scripts/sim_inject_onboard_evade.py
```
→ BLUE 대시보드에 **🚨 SOC 탐지** + 탐지신호(EO/IR 불일치·신뢰도 이상분포)
+ RAG 근거 + LLM 분석 표시 → `[HITL] 자율교전 차단 후 RTB 승인? [y/N]` → `y`
→ QGC 에서 드론 정지(LOITER) 후 복귀(RTL).

## 2. 재촬영(테이크 반복)
```bash
python scripts/sim_inject_onboard_evade.py --clear   # 정상 인식 → 탐지기 재무장
```
BLUE 재시작 불요(자동 재무장). 그 뒤 ②를 다시 실행.

## 참고
- 스트림 경로 변경: `PERCEPTION_STREAM=/path/x.ndjson` 를 BLUE·RED 양쪽에 동일 지정.
- S1(GNSS) 폐루프는 `docs/demo-runbook.md` 참조.
````

- [ ] **Step 2: 전체 포매터·린터·타입·테스트** (CLAUDE.md 자동화 순서)

Run:
```bash
black sim_bridge scripts tests/__tests__/test_sim_bridge.py
ruff check sim_bridge scripts tests/__tests__/test_sim_bridge.py
mypy sim_bridge
pytest tests/__tests__/test_sim_bridge.py -v
```
Expected: black 포맷 통과, ruff 0 error, mypy 0 error(sim_bridge), pytest 전부 PASS(S1 기존 + S8 신규).

> mypy/ruff 가 신규 파일에서 오류를 내면 해당 파일만 수정(타입힌트/임포트 정렬). 기존 미커밋 변경 파일(`agents/`·`core/`)은 건드리지 않는다.

- [ ] **Step 3: 커밋**

```bash
git add docs/demo-runbook-s8.md
git commit -m "docs: S8 온보드 인식 AI 적대공격 시연 녹화 런북"
```

---

## 완료 기준(Definition of Done)

- [ ] `pytest tests/__tests__/test_sim_bridge.py` — S1 기존 + S8 신규 전부 PASS
- [ ] `OnboardAIDetector` 가 정상 인식엔 침묵, 적대(불일치/신뢰도 이상분포)에 발화, 중복억제·재무장 동작
- [ ] `bridge.run_alert(s8_alert)` 가 severity=m / verdict=true_positive / action=response 산출
- [ ] RED 인젝터가 스트림 파일에 정상→적대 레코드 append, BLUE 러너가 tail→탐지→대시보드→HITL→hold→RTB
- [ ] `black/ruff/mypy(sim_bridge)` 통과, 기존 미커밋 변경 보존
- [ ] 라이브 SITL 검증(드론 hold→RTB)은 Opus 가 구현 후 수동 1회 실행으로 확인
```
