"""SOC 탐지 커버리지 KPI — pollack-ai 자체 데이터로 자기완결 정적 대시보드 생성.

blue(SOC) 방어 성숙도를 심사용 정적 HTML로 렌더한다. 데이터는 **pollack-ai 소유**:
  - tools.coverage.CoverageMatrix.report()  (data/attack_coverage.yaml 기준)
  - sentinel/rule_manifest.json             (실제 Sentinel 165 룰)
외부 repo(red) 미의존 = D8 정합. 외부 호스트 0(오프라인), 인라인 SVG+CSS, JS 의존 0.

지표는 전술 커버리지·기법 커버리지·대응가능·탐지룰 수·성숙도(breadth/depth)·
전술별 커버리지·아키타입별 커버리지·미커버 전술(룰 신설 우선순위)로 구성한다.

재생성:  python3 scripts/gen_coverage_kpi.py  ->  app/dashboard_static/coverage-kpi.html
"""
from __future__ import annotations

import html
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools.coverage import CoverageMatrix  # noqa: E402

STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
CAT = ["#2a78d6", "#1baf7a", "#eda100", "#4a3aa7", "#e87ba4"]


def _esc(s):
    return html.escape(str(s))


def _pct(x):
    return f"{100 * x:.1f}%"


def _stacked_bar(segments, width=760, height=26):
    total = sum(c for _, c, _ in segments) or 1
    x, gap, parts, n = 0.0, 2.0, [], len(segments)
    for label, count, color in segments:
        w = (count / total) * (width - gap * (n - 1))
        parts.append(f'<rect x="{x:.1f}" y="0" width="{max(w,0):.1f}" height="{height}" rx="3" '
                     f'fill="{color}"><title>{_esc(label)}: {count} ({_pct(count/total)})</title></rect>')
        x += w + gap
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">{"".join(parts)}</svg>'


def _hbars(items, width=520, maxval=None, fmt=None, row_h=26):
    fmt = fmt or (lambda v: f"{v}")
    maxval = maxval or (max((v for _, v, _ in items), default=1) or 1)
    lab_w, bar_w, rows = 210, width - 210 - 56, []
    for i, (label, value, color) in enumerate(items):
        y = i * row_h
        w = (value / maxval) * bar_w if maxval else 0
        rows.append(
            f'<text x="0" y="{y+row_h/2+4:.0f}" class="lbl">{_esc(label)}</text>'
            f'<rect x="{lab_w}" y="{y+4:.0f}" width="{max(w,1):.1f}" height="{row_h-10}" rx="3" fill="{color}">'
            f'<title>{_esc(label)}: {fmt(value)}</title></rect>'
            f'<text x="{lab_w+w+7:.0f}" y="{y+row_h/2+4:.0f}" class="val">{_esc(fmt(value))}</text>')
    h = len(items) * row_h
    return f'<svg viewBox="0 0 {width} {h}" width="100%" height="{h}" role="img">{"".join(rows)}</svg>'


def _meter(value, status, width=260, height=12):
    v = max(0.0, min(1.0, value))
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">'
            f'<rect x="0" y="0" width="{width}" height="{height}" rx="6" class="track"/>'
            f'<rect x="0" y="0" width="{max(v*width,2):.1f}" height="{height}" rx="6" fill="{status}">'
            f'<title>{_pct(v)}</title></rect></svg>')


def _tile(label, value, sub, status=None):
    accent = f' style="color:{status}"' if status else ""
    return (f'<div class="tile"><div class="tile-label">{_esc(label)}</div>'
            f'<div class="tile-value"{accent}>{_esc(value)}</div>'
            f'<div class="tile-sub">{_esc(sub)}</div></div>')


def _card(title, body, note="", full=False):
    n = f'<p class="card-note">{note}</p>' if note else ""
    cls = "card span-all" if full else "card"
    return f'<section class="{cls}"><h2>{_esc(title)}</h2>{n}{body}</section>'


def _headline(rep, rule_count):
    n_tac = len(rep["tactics"])
    tac_cov = sum(1 for t in rep["tactics"] if t["covered"])
    return '<div class="tiles">' + "".join([
        _tile("전술 커버리지", _pct(tac_cov / n_tac), f"{tac_cov}/{n_tac} ATT&CK 전술 룰 보유", STATUS["good"]),
        _tile("기법 커버리지", _pct(rep["coverage_pct"]), f"{rep['covered']}/{rep['total']} 기법 (대응가능 {_pct(rep['addressable_pct'])})", STATUS["good"]),
        _tile("탐지 룰", str(rule_count), "Sentinel Analytic Rules (dah-sentinel-content)"),
        _tile("성숙도(품질보정)", _pct(rep["quality_adjusted_pct"]), f"네이티브 {rep['native_covered']} · 프록시 {rep['proxy_covered']}", STATUS["serious"]),
    ]) + "</div>"


def _breakdown(rep):
    segs = [("커버", rep["covered"], STATUS["good"]),
            ("계획(planned)", rep["planned"], STATUS["warning"]),
            ("미커버", rep["uncovered"], STATUS["critical"])]
    legend = "".join(f'<span class="leg"><i style="background:{c}"></i>{l} <b>{v}</b></span>' for l, v, c in segs)
    body = f'<div class="bar-wrap">{_stacked_bar(segs)}</div><div class="legend">{legend}</div>'
    return _card("커버리지 분해 (총 %d 기법)" % rep["total"], body,
                 note="ATT&CK 기법 유니버스를 탐지 상태로 분류 — 커버: 탐지룰이 매핑된 기법 · 계획: 탐지 백로그(신설 예정) · 미커버: 탐지 공백.", full=True)


def _tactics(rep):
    tacs = rep["tactics"]
    maxt = max((t["covered"] + t["planned"] + t["uncovered"] for t in tacs), default=1)
    bars = []
    for t in tacs:
        tot = t["covered"] + t["planned"] + t["uncovered"]
        color = STATUS["good"] if t["uncovered"] == 0 else (STATUS["warning"] if t["covered"] else STATUS["critical"])
        bars.append((f"{t['name']} ({t['covered']}/{tot})", t["covered"], color))
    return _card("전술별 탐지 커버리지 (15 전술)",
                 _hbars(bars, width=760, maxval=maxt, fmt=lambda v: str(v)),
                 note="각 ATT&CK 전술에서 탐지룰이 매핑된 기법 수 / 전술 내 전체 기법. 초록=전량 커버, 노랑=일부, 빨강=커버 0.",
                 full=True)


def _depth(rep):
    meters = (
        f'<div class="meter-row"><span>breadth 커버리지</span>{_meter(rep["coverage_pct"], STATUS["good"])}<b>{_pct(rep["coverage_pct"])}</b></div>'
        f'<div class="meter-row"><span>품질보정(depth)</span>{_meter(rep["quality_adjusted_pct"], STATUS["serious"])}<b>{_pct(rep["quality_adjusted_pct"])}</b></div>'
    )
    body = (
        f'{meters}'
        f'<p class="sub"><b>breadth</b>: 탐지룰이 매핑된 기법의 비율(넓이). '
        f'<b>depth(품질보정)</b>: 탐지 품질로 가중한 실효 커버리지 — '
        f'네이티브 탐지(전용 정밀 룰) <b>{rep["native_covered"]}</b> · '
        f'프록시 탐지(간접·추정 룰) <b>{rep["proxy_covered"]}</b>. '
        f'성숙 로드맵은 프록시 룰을 네이티브로 승격하는 것.</p>'
    )
    return _card("탐지 성숙도 — breadth vs depth", body,
                 note="breadth는 '룰이 있는가', depth는 '그 룰이 실제로 정밀하게 잡는가'를 구분한 지표.")


def _archetype(rep):
    ba = rep["by_archetype"] or {}
    bars = [(k, v, CAT[i % len(CAT)]) for i, (k, v) in enumerate(sorted(ba.items()))]
    return _card("공격 아키타입별 커버 기법", _hbars(bars, width=520, fmt=lambda v: str(v)),
                 note="공격 유형(사전침해·수동수집·암호화 C2·파괴예방 등)별로 탐지룰이 커버하는 기법 수.")


def _gaps(rep):
    gaps = [t for t in rep["tactics"] if t["uncovered"] > 0]
    rows = "".join(f'<tr><td>{_esc(t["name"])}</td><td>{t["uncovered"]}</td><td>{t["covered"]}/{t["covered"]+t["planned"]+t["uncovered"]}</td></tr>'
                   for t in sorted(gaps, key=lambda x: -x["uncovered"]))
    body = f'<table class="rx"><thead><tr><th>전술</th><th>미커버</th><th>현재</th></tr></thead><tbody>{rows}</tbody></table>'
    return _card("🔧 다음 룰 신설 우선순위 (미커버 전술)", body,
                 note="미커버 기법이 남은 전술 = 탐지룰 신설 백로그.", full=True)


_CSS = """
:root{--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--ring:rgba(11,11,11,.10);--track:#ecebe6;}
@media (prefers-color-scheme:dark){:root{--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--grid:#2c2c2a;--ring:rgba(255,255,255,.10);--track:#2c2c2a;}}
:root[data-theme=light]{--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--grid:#e1e0d9;--ring:rgba(11,11,11,.10);--track:#ecebe6;}
:root[data-theme=dark]{--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--grid:#2c2c2a;--ring:rgba(255,255,255,.10);--track:#2c2c2a;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}
.wrap{max-width:1440px;margin:0 auto;padding:32px 28px 64px}
header h1{font-size:24px;margin:0 0 4px}header .lede{color:var(--ink2);margin:0 0 4px;font-size:15px}header .meta{color:var(--muted);font-size:13px;margin:0}
.defs{margin:16px 0 4px;padding:14px 16px;background:var(--surface);border:1px solid var(--ring);border-radius:12px;display:grid;gap:6px;font-size:13px;color:var(--ink2)}
.defs > b{color:var(--ink);font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.defs span b{color:var(--ink)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0 24px}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:12px;padding:16px}
.tile-label{color:var(--ink2);font-size:13px}.tile-value{font-size:30px;font-weight:700;margin:4px 0}.tile-sub{color:var(--muted);font-size:12px}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:stretch;margin-top:16px}
.cards .card{margin:0;height:100%}.card.span-all{grid-column:1/-1}
@media (max-width:860px){.cards{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:12px;padding:20px}
.card h2{font-size:17px;margin:0 0 4px}.card-note{color:var(--muted);font-size:13px;margin:0 0 14px}
.bar-wrap{margin:6px 0 12px}.legend{display:flex;flex-wrap:wrap;gap:14px}.leg{font-size:13px;color:var(--ink2)}
.leg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle}.leg b{color:var(--ink)}
svg .lbl{fill:var(--ink2);font-size:12px}svg .val{fill:var(--ink);font-size:12px;font-variant-numeric:tabular-nums}svg .track{fill:var(--track)}
.meter-row{display:grid;grid-template-columns:130px 1fr 56px;align-items:center;gap:10px;margin:8px 0;font-size:13px;color:var(--ink2)}
.meter-row b{color:var(--ink);text-align:right;font-variant-numeric:tabular-nums}
.sub{color:var(--ink2);font-size:13px;margin:10px 0 6px}.sub b{color:var(--ink)}
.rx{width:100%;border-collapse:collapse;font-size:13px}.rx th,.rx td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid)}.rx th{color:var(--muted);font-weight:600}
footer{color:var(--muted);font-size:12px;margin-top:28px;border-top:1px solid var(--grid);padding-top:14px}footer code{font-size:11px}
"""


def render_html():
    rep = CoverageMatrix.from_yaml().report().model_dump()
    manifest = json.load(open(os.path.join(ROOT, "sentinel", "rule_manifest.json"), encoding="utf-8"))
    rule_count = manifest.get("_rule_count", 0)
    cards = "".join([_breakdown(rep), _tactics(rep), _depth(rep), _archetype(rep), _gaps(rep)])
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC 탐지 커버리지 KPI — pollack-ai</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header>
<h1>SOC 탐지 커버리지 KPI</h1>
<p class="lede">UAV AI SOC의 ATT&amp;CK 탐지 커버리지 · 방어 성숙도. pollack-ai 자체 데이터 산출.</p>
<p class="meta">source: <code>tools.coverage</code>(attack_coverage.yaml) + <code>rule_manifest.json</code>(실 165룰) · 무의존·결정론</p>
</header>
<div class="defs">
<b>지표 정의</b>
<span><b>전술 커버리지</b> — ATT&amp;CK 15개 전술 중 최소 1개 탐지룰을 보유한 전술 비율.</span>
<span><b>기법 커버리지</b> — 전체 ATT&amp;CK 기법 중 탐지룰이 매핑된 기법 비율(대응가능 = 커버+계획).</span>
<span><b>탐지 룰</b> — 배포된 Sentinel Analytic Rule 수.</span>
<span><b>성숙도(품질보정)</b> — 탐지 품질(네이티브/프록시)로 가중한 실효 커버리지.</span>
</div>
{_headline(rep, rule_count)}
<div class="cards">
{cards}
</div>
<footer>
<b>산출 방법</b>: ATT&amp;CK 기법 유니버스(<code>data/attack_coverage.yaml</code>)에 배포된 Sentinel
Analytic Rule(<code>sentinel/rule_manifest.json</code>, {rule_count}룰)을 매핑해 전술·기법·아키타입별
커버리지를 계산한다. 무의존·결정론(동일 입력 → 동일 출력).
재생성: <code>python3 scripts/gen_coverage_kpi.py</code>.
</footer>
</div></body></html>"""


def main():
    out = os.path.join(ROOT, "app", "dashboard_static", "coverage-kpi.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render_html())
    print(f"[SOC 커버리지 KPI] {out}")
    return out


if __name__ == "__main__":
    main()
