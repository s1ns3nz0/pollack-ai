#!/usr/bin/env python3
"""시뮬 라이브 GCS 세션 emitter — `UAVGcsAccess_CL` 적재 워커.

`sim_bridge.gcs_access_synth` 가 만든 정상 베이스라인 + 공격 페어를 Logs Ingestion
API 로 적재한다. 두 모드:

- **dry-run(기본)**: `--out <dir>` 에 한 사이클 행을 JSON 으로 저장(검토용).
- **--post**: DCE/DCR 로 직접 POST(`scripts.gen_table_testdata.post_rows` 재사용).

사이클당 정상 N건 + (옵션) 하이재킹 1건 / 무차별 3건. `--interval` 로 사이클 주기
(초)를 지정하면 무한 루프(시뮬 라이브 모드).

토큰:
  TOKEN=$(az account get-access-token --resource https://monitor.azure.com \
            --query accessToken -o tsv)

사용 예:
  # dry-run
  python scripts/sim_emit_gcs.py --out scripts/testdata/gcs

  # 1회 적재
  python scripts/sim_emit_gcs.py --post --endpoint $DCE --dcr-id $DCR --token $TOKEN

  # 라이브 (5초마다 사이클)
  python scripts/sim_emit_gcs.py --post --endpoint $DCE --dcr-id $DCR \
    --token $TOKEN --interval 5 --normal 10
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from scripts.gen_table_testdata import post_rows
from sim_bridge.gcs_access_synth import records_to_rows, synth_records

TABLE = "UAVGcsAccess_CL"


def _build_cycle_rows(args: argparse.Namespace) -> list[dict[str, object]]:
    records = synth_records(
        benign_n=args.normal,
        include_hijack=not args.no_hijack,
        include_brute_force=args.brute_force,
        seed=args.seed,
    )
    return records_to_rows(records)


def _run_once(args: argparse.Namespace) -> int:
    rows = _build_cycle_rows(args)
    if args.post:
        code = post_rows(args.endpoint, args.dcr_id, args.token, TABLE, rows)
        print(f"POST {TABLE}: {len(rows)}행 → HTTP {code}")
        return 0 if 200 <= code < 300 else 1
    out_dir = Path(args.out or (Path(__file__).resolve().parents[1] / "scripts" / "testdata" / "gcs"))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{TABLE}.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"wrote {TABLE}.json ({len(rows)}행) → {out_dir}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="UAVGcsAccess_CL 라이브 emitter")
    ap.add_argument("--out", help="dry-run: 행을 이 디렉토리에 저장")
    ap.add_argument("--post", action="store_true", help="Logs Ingestion API 로 적재")
    ap.add_argument("--endpoint", help="DCE ingestion 엔드포인트")
    ap.add_argument("--dcr-id", help="DCR immutableId")
    ap.add_argument("--token", help="Bearer 토큰(monitor.azure.com)")
    ap.add_argument("--normal", type=int, default=10, help="사이클당 정상 건수")
    ap.add_argument("--no-hijack", action="store_true", help="하이재킹 1건 제외")
    ap.add_argument("--brute-force", action="store_true", help="무차별 인증 3건 추가")
    ap.add_argument("--interval", type=float, default=0.0, help="사이클 주기(초), 0이면 1회만")
    ap.add_argument("--seed", type=int, help="결정론 모드(테스트용)")
    args = ap.parse_args()

    if args.post and not (args.endpoint and args.dcr_id and args.token):
        print("--post 에는 --endpoint/--dcr-id/--token 필요", file=sys.stderr)
        return 2

    if args.interval <= 0:
        return _run_once(args)

    while True:
        try:
            _run_once(args)
        except Exception as exc:  # noqa: BLE001 - 한 사이클 실패가 워커를 죽이지 않게
            print(f"사이클 실패(계속): {exc}", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
