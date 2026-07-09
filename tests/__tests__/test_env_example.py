"""환경변수 예시 파일이 Settings 운영 플래그를 노출하는지 검증."""

from __future__ import annotations

from pathlib import Path


def test_env_example_documents_operational_feature_flags() -> None:
    """운영자가 opt-in 기능을 켤 수 있게 .env.example 에 키가 있어야 한다."""
    body = Path(".env.example").read_text(encoding="utf-8")
    required = {
        "LINEAGE_ENABLED=",
        "RAGAS_FAITHFULNESS_THRESHOLD=",
        "RAGAS_ANSWER_RELEVANCY_THRESHOLD=",
        "RAGAS_CONTEXT_RELEVANCY_THRESHOLD=",
        "CYBER_POSTURE_LEVEL=",
        "PREDICT_MIN_SUPPORT=",
        "PREDICT_MIN_PROBABILITY=",
        "PREDICT_TOP_K=",
        "CAUSAL_RULES_PATH=",
        "CAUSAL_LLM_EXPLAIN=",
        "ATTACK_FEED_URL=",
        "ATLAS_FEED_URL=",
        "EMBED3D_FEED_URL=",
        "KEV_FEED_URL=",
        "FEED_REFRESH_HOURS=",
        "FEED_USER_AGENT=",
        "FEED_ADDED_CAP=",
        "AUTO_KQL_ENABLED=",
        "AUTO_KQL_MAX_TECHNIQUES=",
        "ACTIVE_HUNT_ENABLED=",
        "ACTIVE_HUNT_POLICY_PATH=",
    }

    missing = sorted(key for key in required if key not in body)

    assert not missing
