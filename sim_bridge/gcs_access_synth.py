"""GCS 원격접속(noVNC/VNC/QGC) 세션 이벤트 합성기 + Logs Ingestion 전송.

`sim_bridge/synth.py`(MAVLink telemetry-tap) 와 동일 패턴: 정상 베이스라인 N 건 후
공격(외부IP·세션재사용·대용량 = T1078/T1185/Exfil) 1 건을 주입한다. 출력 dict 는
`UAVGcsAccess_CL` 스키마(`deploy/sentinel-tables/UAVGcsAccess_CL.json`)와 일치해
DCR `Custom-UAVGcsAccess_CL` 스트림으로 그대로 적재된다.

POST 통로는 `scripts.gen_table_testdata.post_rows` 를 재사용한다(URL 패턴/헤더 단일
진실원). 실시간 emit 은 `emit_stream()` 비동기 제너레이터 또는 `run_live()` 루퍼로.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime, timedelta
import random

from sim_bridge.models import GcsAccessRecord

INTERNAL_OPS = ("sgt.yang", "lt.kim", "capt.park")
INTERNAL_TRANSPORTS = ("novnc", "qgc", "vnc")


def _iso(offset_sec: int = 0) -> str:
    """현재 UTC 기준 `-offset_sec` 시각 ISO8601(Z)."""
    ts = datetime.now(UTC) - timedelta(seconds=offset_sec)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def benign_session(i: int = 0, rng: random.Random | None = None) -> GcsAccessRecord:
    """정상 내부망 GCS 세션 한 건(`10.10.0.0/24`, 내부 운용자, 소규모 트래픽)."""
    r = rng or random
    return GcsAccessRecord(
        TimeGenerated=_iso(i),
        SessionId=f"sess-{2000 + i}",
        ClientIp=f"10.10.0.{r.randint(2, 30)}",
        Transport=r.choice(INTERNAL_TRANSPORTS),
        Operator=r.choice(INTERNAL_OPS),
        Action=r.choice(("connect", "auth", "disconnect")),
        UserAgent="QGC/4.3",
        BytesSent=r.randint(1000, 200000),
        BytesReceived=r.randint(1000, 50000),
        DurationSec=float(r.randint(30, 900)),
        Result="ok",
    )


def hijack_session(i: int = 0) -> GcsAccessRecord:
    """외부 비인가 IP + 동일 SessionId 재사용 + 대용량 = 하이재킹/캡처(T1078/T1185)."""
    return GcsAccessRecord(
        TimeGenerated=_iso(i),
        SessionId="sess-1001",  # 정상 세션과 동일 ID 재사용 → 하이재킹 신호
        ClientIp="203.0.113.66",  # 비인가 외부 대역(TEST-NET-3)
        Transport="novnc",
        Operator="unknown",
        Action="connect",
        UserAgent="Mozilla/5.0",
        BytesSent=524_288_000,  # 500MB ≈ 화면/영상 캡처 Exfil
        BytesReceived=1_048_576,
        DurationSec=3600.0,
        Result="ok",
    )


def brute_force_session(
    i: int = 0, rng: random.Random | None = None
) -> GcsAccessRecord:
    """자격증명 무차별(T1110) — `Action=auth` + `Result=fail`."""
    r = rng or random
    return GcsAccessRecord(
        TimeGenerated=_iso(i),
        SessionId=f"sess-bf-{i}",
        ClientIp=f"198.51.100.{r.randint(10, 200)}",  # 외부 TEST-NET-2
        Transport="novnc",
        Operator="unknown",
        Action="auth",
        UserAgent="curl/8.0",
        BytesSent=512,
        BytesReceived=128,
        DurationSec=0.4,
        Result="fail",
    )


def synth_records(
    benign_n: int = 5,
    *,
    include_hijack: bool = True,
    include_brute_force: bool = False,
    seed: int | None = None,
) -> list[GcsAccessRecord]:
    """정상 N건 + (옵션) 하이재킹 1건 + (옵션) 무차별 인증 3건 시퀀스."""
    rng = random.Random(seed)  # noqa: S311 - 합성 텔레메트리(비암호용)
    out: list[GcsAccessRecord] = [benign_session(i, rng) for i in range(benign_n)]
    if include_brute_force:
        out.extend(brute_force_session(i, rng) for i in range(3))
    if include_hijack:
        out.append(hijack_session(benign_n))
    return out


async def emit_stream(
    benign_n: int = 5,
    *,
    include_hijack: bool = True,
    include_brute_force: bool = False,
    seed: int | None = None,
) -> AsyncIterator[GcsAccessRecord]:
    """비동기 스트림 — `SimBridge.run_stream` 패턴과 동일 시그니처."""
    for record in synth_records(
        benign_n,
        include_hijack=include_hijack,
        include_brute_force=include_brute_force,
        seed=seed,
    ):
        yield record


def records_to_rows(records: Iterable[GcsAccessRecord]) -> list[dict[str, object]]:
    """레코드 → Logs Ingestion API POST 행 배열."""
    return [r.to_row() for r in records]
