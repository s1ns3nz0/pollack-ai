#!/usr/bin/env python3
"""신규 커스텀 테이블 테스트 데이터 생성기 — 정상 + 공격 행.

`deploy/sentinel-tables/*.json` 의 컬럼을 단일 진실로 삼아, 4개 테이블에 대해
정상 baseline + 탐지가 발화할 공격 행을 섞어 만든다. 두 모드:

- **dry-run(기본)**: `--out <dir>` 에 `<Table>.json`(행 배열) 저장 → 검토/수동 POST.
- **--post**: Logs Ingestion API 로 직접 적재(엔드포인트/DCR immutableId/토큰 필요).

토큰:  az account get-access-token --resource https://monitor.azure.com \
         --query accessToken -o tsv
사용 예:
  python scripts/gen_table_testdata.py --out scripts/testdata
  python scripts/gen_table_testdata.py --post \
    --endpoint https://dce-...ingest.monitor.azure.com \
    --dcr-id <immutableId> --token "$TOKEN" --normal 50 --attack 5
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import random
import sys

import httpx

ROOT = Path(__file__).resolve().parents[1]
TABLE_DIR = ROOT / "deploy" / "sentinel-tables"
_API = "2023-01-01"


def _now_iso(offset_sec: int = 0) -> str:
    ts = datetime.now(UTC) - timedelta(seconds=offset_sec)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── 테이블별 행 생성기 (정상/공격) ──────────────────────────
def _gcs_access(attack: bool, i: int) -> dict[str, object]:
    if attack:  # 외부 IP·세션 재사용·대용량 전송(세션 하이재킹/화면 캡처)
        return {
            "TimeGenerated": _now_iso(i),
            "SessionId": "sess-1001",  # 동일 세션 IP 불일치
            "ClientIp": "203.0.113.66",  # 비인가 외부 대역
            "Transport": "novnc",
            "Operator": "unknown",
            "Action": "connect",
            "UserAgent": "Mozilla/5.0",
            "BytesSent": 524288000,  # 대용량 = 화면/영상 캡처 의심
            "BytesReceived": 1048576,
            "DurationSec": 3600.0,
            "Result": "ok",
        }
    op = random.choice(["sgt.yang", "lt.kim", "capt.park"])
    return {
        "TimeGenerated": _now_iso(i),
        "SessionId": f"sess-{2000 + i}",
        "ClientIp": f"10.10.0.{random.randint(2, 30)}",
        "Transport": random.choice(["novnc", "qgc", "vnc"]),
        "Operator": op,
        "Action": random.choice(["connect", "disconnect", "auth"]),
        "UserAgent": "QGC/4.3",
        "BytesSent": random.randint(1000, 200000),
        "BytesReceived": random.randint(1000, 50000),
        "DurationSec": float(random.randint(30, 900)),
        "Result": "ok",
    }


def _router_stats(attack: bool, i: int) -> dict[str, object]:
    if attack:  # 비인가 PeerIp + CRC 오류 급증(MAVLink C2/프록시)
        return {
            "TimeGenerated": _now_iso(i),
            "EndpointName": "udp-unknown",
            "PeerIp": "203.0.113.77",
            "PeerPort": 5790,
            "Protocol": "udp",
            "MsgTx": 50000,
            "MsgRx": 48000,
            "CrcErrors": 1800,  # 정상 대비 급증
            "DropCount": 320,
        }
    return {
        "TimeGenerated": _now_iso(i),
        "EndpointName": random.choice(["uart0", "udp-gcs", "tcp-bridge"]),
        "PeerIp": f"10.20.0.{random.randint(2, 20)}",
        "PeerPort": random.choice([5760, 5762, 14550]),
        "Protocol": random.choice(["udp", "tcp", "serial"]),
        "MsgTx": random.randint(1000, 20000),
        "MsgRx": random.randint(1000, 20000),
        "CrcErrors": random.randint(0, 5),
        "DropCount": random.randint(0, 10),
    }


def _imagery(attack: bool, i: int) -> dict[str, object]:
    if attack:  # 스트림 끊김/열화(Denial/Loss of View)
        return {
            "TimeGenerated": _now_iso(i),
            "UAVId": "UAV-ANHEUNG-07",
            "StreamId": "eo-01",
            "MsgType": "STREAM_STATUS",
            "EventType": random.choice(["gap", "degraded"]),
            "FrameRate": 2.0,  # 정상 30 대비 급락
            "GapMs": random.randint(3000, 15000),
            "Resolution": "1920x1080",
        }
    return {
        "TimeGenerated": _now_iso(i),
        "UAVId": f"UAV-ANHEUNG-{random.randint(1, 9):02d}",
        "StreamId": random.choice(["eo-01", "ir-01"]),
        "MsgType": "FRAME",
        "EventType": "frame",
        "FrameRate": float(random.choice([24, 30, 60])),
        "GapMs": random.randint(0, 50),
        "Resolution": "1920x1080",
    }


def _file_audit(attack: bool, i: int) -> dict[str, object]:
    if attack:  # 로그/임무 파일 삭제·스테이징(데이터파괴/Collection)
        return {
            "TimeGenerated": _now_iso(i),
            "ContainerName": "mavlink-router",
            "Pid": random.randint(1000, 9000),
            "ProcessName": "rm",
            # 첫 공격행은 delete 보장(데이터파괴 신호 결정성 — 테스트 flaky 방지),
            # 나머지는 변형(read 열람도 Collection 신호).
            "Operation": "delete" if i == 0 else random.choice(["delete", "read"]),
            "FilePath": random.choice(
                ["/var/log/uav/audit.log", "/data/missions/plan.json"]
            ),
            "BytesAccessed": random.randint(10000, 5000000),
            "User": "root",
            "Syscall": random.choice(["unlink", "openat"]),
        }
    return {
        "TimeGenerated": _now_iso(i),
        "ContainerName": random.choice(["telemetry-tap", "gcs-stub"]),
        "Pid": random.randint(100, 999),
        "ProcessName": random.choice(["python3", "telemetryd"]),
        "Operation": random.choice(["read", "write", "exec"]),
        "FilePath": "/app/telemetry/buffer.dat",
        "BytesAccessed": random.randint(100, 100000),
        "User": "soc",
        "Syscall": "read",
    }


_GENERATORS = {
    "UAVGcsAccess_CL": _gcs_access,
    "UAVRouterStats_CL": _router_stats,
    "UAVImagery_CL": _imagery,
    "UAVFileAudit_CL": _file_audit,
}


def table_columns(table: str) -> set[str]:
    """테이블 ARM 에서 컬럼명 집합을 읽는다(단일 진실)."""
    arm = json.loads((TABLE_DIR / f"{table}.json").read_text(encoding="utf-8"))
    cols = arm["resources"][0]["properties"]["schema"]["columns"]
    return {c["name"] for c in cols}


def build_rows(table: str, n_normal: int = 50, n_attack: int = 5) -> list[dict]:
    """테이블의 정상 + 공격 행을 생성한다(컬럼은 ARM 스키마에 일치)."""
    gen = _GENERATORS[table]
    rows = [gen(False, i) for i in range(n_normal)]
    rows += [gen(True, i) for i in range(n_attack)]
    cols = table_columns(table)
    for r in rows:  # 스키마에 없는 키 방지(방어)
        unknown = set(r) - cols
        if unknown:
            raise ValueError(f"{table}: 스키마 밖 컬럼 {unknown}")
    random.shuffle(rows)
    return rows


def post_rows(
    endpoint: str,
    dcr_immutable_id: str,
    token: str,
    table: str,
    rows: list[dict],
    client_factory: object | None = None,
) -> int:
    """Logs Ingestion API 로 행을 적재하고 HTTP 상태코드를 반환한다."""
    url = (
        f"{endpoint.rstrip('/')}/dataCollectionRules/{dcr_immutable_id}"
        f"/streams/Custom-{table}?api-version={_API}"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    client = (
        client_factory() if client_factory is not None else httpx.Client(timeout=30.0)
    )
    with client:
        resp = client.post(url, headers=headers, json=rows)
    return resp.status_code


def main() -> int:
    ap = argparse.ArgumentParser(description="커스텀 테이블 테스트 데이터 생성/적재")
    ap.add_argument("--out", help="dry-run: 이 디렉토리에 <Table>.json 저장")
    ap.add_argument("--post", action="store_true", help="Logs Ingestion API 로 적재")
    ap.add_argument("--endpoint", help="DCE ingestion 엔드포인트")
    ap.add_argument("--dcr-id", help="DCR immutableId")
    ap.add_argument("--token", help="Bearer 토큰(monitor.azure.com)")
    ap.add_argument("--normal", type=int, default=50)
    ap.add_argument("--attack", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    data = {t: build_rows(t, args.normal, args.attack) for t in _GENERATORS}

    if args.post:
        if not (args.endpoint and args.dcr_id and args.token):
            print("--post 에는 --endpoint/--dcr-id/--token 필요", file=sys.stderr)
            return 2
        for table, rows in data.items():
            code = post_rows(args.endpoint, args.dcr_id, args.token, table, rows)
            print(f"POST {table}: {len(rows)}행 → HTTP {code}")
        return 0

    out_dir = Path(args.out or (ROOT / "scripts" / "testdata"))
    out_dir.mkdir(parents=True, exist_ok=True)
    for table, rows in data.items():
        (out_dir / f"{table}.json").write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"wrote {table}.json ({len(rows)}행)")
    print(f"→ {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
