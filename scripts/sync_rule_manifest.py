"""dah-sentinel-content 의 Analytic Rule 카탈로그를 pollack-ai 로컬 매니페스트로 동기화.

golden fixture(`benchmarks/eval_scenarios/*.yaml`)의 `expected_detection.sentinel_rule`
참조가 실제 Sentinel 분석룰을 가리키는지 CI 에서 hermetic 하게 검증하려면, 별도 레포
(dah-sentinel-content)의 룰 목록 스냅샷이 이 레포 안에 있어야 한다. 이 스크립트가 그
스냅샷(`sentinel/rule_manifest.json`)을 생성한다.

각 룰 JSON 에서 파일명 + `properties.tactics/techniques` 를 추출해 매니페스트에 담고,
소스 레포 커밋 SHA 를 핀으로 박는다. CI 는 커밋된 매니페스트만 읽으므로 형제 레포가
없어도 게이트가 돈다. 드리프트(형제 레포 룰 추가·개명)는 개발자가 이 스크립트를 다시
돌려 수동 갱신한다.

사용:
    python scripts/sync_rule_manifest.py \\
        --source /Users/s1ns3nz0/dah-sentinel-content
    # 또는 env DAH_SENTINEL_PATH 로 소스 경로 지정 (기본 ../dah-sentinel-content)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # noqa: S404 — git rev-parse 로 소스 SHA 핀만 읽는다(신뢰 경로).
from pathlib import Path
from typing import TypedDict


class RuleEntry(TypedDict):
    """매니페스트 내 룰 1건 — MITRE 정합 대조에 쓰는 최소 필드."""

    tactics: list[str]
    techniques: list[str]


class Manifest(TypedDict):
    """rule_manifest.json 전체 구조."""

    _source: str
    _source_sha: str
    _generated_by: str
    _rule_count: int
    rules: dict[str, RuleEntry]


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_PATH = _REPO_ROOT / "sentinel" / "rule_manifest.json"
_GENERATED_BY = "scripts/sync_rule_manifest.py"


def _default_source() -> Path:
    """소스 레포 경로 기본값 — env `DAH_SENTINEL_PATH` 우선, 없으면 형제 디렉터리."""
    env = os.environ.get("DAH_SENTINEL_PATH")
    if env:
        return Path(env)
    return _REPO_ROOT.parent / "dah-sentinel-content"


def _read_source_sha(source: Path) -> str:
    """소스 레포의 현재 커밋 SHA. git 정보가 없으면 'unknown'."""
    try:
        out = subprocess.run(  # noqa: S603 — 인자 고정, 셸 미사용.
            ["git", "-C", str(source), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _extract_entry(rule_json: dict[str, object]) -> RuleEntry:
    """룰 JSON(ARM 템플릿)에서 tactics/techniques 추출.

    Args:
        rule_json: `resources[0].properties` 를 포함한 ARM 배포 템플릿 딕셔너리.

    Returns:
        tactics/techniques 만 담은 최소 엔트리(없으면 빈 리스트).
    """
    resources = rule_json.get("resources")
    if not isinstance(resources, list) or not resources:
        return {"tactics": [], "techniques": []}
    first = resources[0]
    props = first.get("properties") if isinstance(first, dict) else None
    if not isinstance(props, dict):
        return {"tactics": [], "techniques": []}
    tactics = props.get("tactics") or []
    techniques = props.get("techniques") or []
    return {
        "tactics": [str(t) for t in tactics if isinstance(t, str)],
        "techniques": [str(t) for t in techniques if isinstance(t, str)],
    }


def build_manifest(source: Path) -> Manifest:
    """소스 레포의 AnalyticsRules 를 스캔해 매니페스트를 만든다.

    Args:
        source: dah-sentinel-content 체크아웃 루트.

    Returns:
        rule_manifest.json 에 직렬화할 매니페스트.

    Raises:
        FileNotFoundError: `<source>/AnalyticsRules` 가 없을 때.
    """
    rules_dir = source / "AnalyticsRules"
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"AnalyticsRules 디렉터리 없음: {rules_dir}")

    rules: dict[str, RuleEntry] = {}
    for path in sorted(rules_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        rules[path.name] = _extract_entry(data)

    return {
        "_source": "github.com/s1ns3nz0/dah-sentinel-content",
        "_source_sha": _read_source_sha(source),
        "_generated_by": _GENERATED_BY,
        "_rule_count": len(rules),
        "rules": rules,
    }


def write_manifest(manifest: Manifest, path: Path = _MANIFEST_PATH) -> None:
    """매니페스트를 정렬된 JSON 으로 기록(결정론적 diff)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    """CLI 진입점."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=_default_source(),
        help="dah-sentinel-content 체크아웃 경로 (기본: env DAH_SENTINEL_PATH 또는 형제 디렉터리)",
    )
    args = parser.parse_args()

    manifest = build_manifest(args.source)
    write_manifest(manifest)
    print(  # noqa: T201 — CLI 도구(스크립트 계층, print 규칙 예외).
        f"매니페스트 갱신: {manifest['_rule_count']}개 룰 "
        f"@ {manifest['_source_sha'][:12]} -> {_MANIFEST_PATH}"
    )


if __name__ == "__main__":
    main()
