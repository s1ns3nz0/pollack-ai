"""Inbound 신뢰경계 — whitelist wire 모델로 enrich/authority 필드 위조 근절.

핵심 불변식:
- untrusted payload 의 내부전용 12필드 위조 → to_alert 후 전부 Alert 기본값.
- drift 가드: Alert 필드 = wire 필드 ∪ 내부전용12(신규 필드 분류 강제).
- 의미적 트리거링(서술필드→파생플래그)은 escalation-only 로 수용(억제 불가).
"""

from core.models import (
    _INTERNAL_ONLY_FIELDS,
    Alert,
    Severity,
    UntrustedAlertPayload,
    Verdict,
    has_forged_internal_fields,
)


def _wire_payload(**extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S1",
        "title": "t",
        "time_generated": "2026-07-09T12:00:00Z",
        "asset_id": "GNSS",
        "mission_phase": "ingress",
        "severity_baseline": "m",
        "signals": ["sig"],
    }
    base.update(extra)
    return base


class TestDriftGuard:
    """신규 필드 분류 강제 — 실패하면 새 Alert 필드를 wire/내부로 분류하라는 신호."""

    def test_alert_fields_partitioned(self) -> None:
        alert_fields = set(Alert.model_fields)
        wire_fields = set(UntrustedAlertPayload.model_fields)
        # wire 는 Alert 의 부분집합
        assert wire_fields <= alert_fields
        # Alert = wire ∪ 내부전용, 겹침 없음
        assert wire_fields | _INTERNAL_ONLY_FIELDS == alert_fields
        assert wire_fields & _INTERNAL_ONLY_FIELDS == set()


class TestForgeryBlocked:
    """내부전용 필드 위조 → 기본값 강제."""

    def test_escalation_flags_dropped(self) -> None:
        """decoy_hit/key_terrain/kill_chain_advanced/prediction_match 위조 → False."""
        payload = _wire_payload(
            decoy_hit=True,
            key_terrain=True,
            kill_chain_advanced=True,
            prediction_match=True,
        )
        alert = UntrustedAlertPayload.model_validate(payload).to_alert()
        assert not alert.decoy_hit
        assert not alert.key_terrain
        assert not alert.kill_chain_advanced
        assert not alert.prediction_match

    def test_suppression_fields_dropped(self) -> None:
        """no_effect_sustained/ground_truth 위조 → 기본값(억제 차단, Codex Critical)."""
        payload = _wire_payload(no_effect_sustained=True, ground_truth="false_positive")
        alert = UntrustedAlertPayload.model_validate(payload).to_alert()
        assert alert.no_effect_sustained is False
        assert alert.ground_truth == Verdict.TRUE_POSITIVE  # 기본값 유지

    def test_authority_fields_dropped(self) -> None:
        """posture/defense_playbook/expected_detection/actor_id 위조 → 기본값."""
        payload = _wire_payload(
            posture="high",
            defense_playbook={"id": "evil"},
            expected_detection={"sigma_rule": "attacker.yml"},
            actor_id="spoofed",
            dwelling_min=999,
            lateral_correlation=True,
        )
        alert = UntrustedAlertPayload.model_validate(payload).to_alert()
        assert alert.posture == "normal"
        assert alert.defense_playbook == {}
        assert alert.expected_detection == {}
        assert alert.actor_id is None
        assert alert.dwelling_min == 0
        assert alert.lateral_correlation is False

    def test_descriptive_fields_preserved(self) -> None:
        """정상 위협 서술 필드는 그대로 전달."""
        payload = _wire_payload(
            asset_id="C2_LINK",
            iocs=["1.2.3.4"],
            mitre={"techniques": ["T1071"]},
            time_generated="2026-07-09T13:14:15Z",
        )
        alert = UntrustedAlertPayload.model_validate(payload).to_alert()
        assert alert.asset_id == "C2_LINK"
        assert alert.iocs == ["1.2.3.4"]
        assert alert.mitre == {"techniques": ["T1071"]}
        assert alert.time_generated == "2026-07-09T13:14:15Z"
        assert alert.severity_baseline == Severity.MEDIUM


class TestForgeryTelemetry:
    """위조 시도 탐지(로깅 입력)."""

    def test_detects_forged_keys(self) -> None:
        forged = has_forged_internal_fields(
            _wire_payload(decoy_hit=True, actor_id="x", ground_truth="fp")
        )
        assert set(forged) == {"decoy_hit", "actor_id", "ground_truth"}

    def test_clean_payload_no_forgery(self) -> None:
        assert has_forged_internal_fields(_wire_payload()) == []

    def test_non_dict_safe(self) -> None:
        assert has_forged_internal_fields("nope") == []


class TestSeverityBaselineBounded:
    """severity_baseline(탐지소스 필드, wire) 위조는 억제 불가 — 내부 modifier 가 격상.

    Codex diff High 반영: baseline 은 자문 시작점일 뿐. 위조 저-baseline 실공격도
    핵심자산이면 내부 modifier(key_terrain 등)가 baseline 무관하게 격상한다.
    """

    def test_forged_low_baseline_still_escalates(self) -> None:
        from core.severity import SeverityEngine

        eng = SeverityEngine()
        # 공격자가 baseline=info 로 위조했으나 자산이 핵심지형(내부 enricher 가 세팅)
        alert = Alert(
            id="a1",
            scenario_id="S1",
            title="t",
            asset_id="GNSS",
            asset_tier="T1-Critical",
            mission_phase="ingress",
            severity_baseline=Severity.INFO,
            signals=["sig"],
            key_terrain=True,  # 내부 enricher 산출(위조 불가 경로)
        )
        level, rationale = eng.compute(alert)
        # info 시작이지만 자산/핵심지형 modifier 로 격상 — 억제 안 됨
        assert eng.ordinal[str(level)] > eng.ordinal["i"]
        assert any("key_terrain" in r or "asset" in r for r in rationale)


class TestSemanticTriggeringAccepted:
    """의미적 트리거링 — 서술필드가 파생플래그 유발은 설계상 정상(escalation-only)."""

    def test_wire_alert_can_still_be_enriched_by_pipeline(self) -> None:
        """wire 에서 온 alert 도 파이프라인 enricher 가 파생플래그 세팅 가능(정상).

        미끼 자산 접촉(asset_id)이 decoy_hit 을 유발하는 건 '탐지 작동' — 막지 않는다.
        위조 차단은 *직접 플래그 할당* 만; 위협 내용→탐지 유발은 정상.
        """
        from core.deception import DecoyDetector

        alert = UntrustedAlertPayload.model_validate(
            _wire_payload(asset_id="GCS_HONEY")
        ).to_alert()
        assert alert.decoy_hit is False  # to_alert 시점엔 미설정
        # enricher 통과 후엔 파생 설정됨(탐지 정상 작동)
        det = DecoyDetector(decoy_assets={"GCS_HONEY"}, canary_hashes=set())
        import asyncio

        enriched = asyncio.run(det.enrich(alert))
        assert enriched.decoy_hit is True
