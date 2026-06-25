#!/usr/bin/env python3
"""replay_traj.json + three.js → 자체완결 3D 리플레이 HTML."""
import json
import os

os.chdir(os.path.expanduser("~/pollack-ai"))
REC = "s8-demo-recording"
traj = json.load(open(f"{REC}/replay_traj.json"))
three = open("/tmp/three.min.js").read()
orbit = open("/tmp/OrbitControls.js").read()

# 실제 SOC 동작 값(검증된 S1 GPS 스푸핑 대응)
soc = {
    "title": "GPS/GNSS 스푸핑 의심 (시뮬 실시간 탐지)",
    "signals": "EKF PosHorizVariance 급증(4.8≥0.8), 위성수 급감(5<7)",
    "severity": "h",
    "rag": [
        "kb/ieee_uav_attack_gps_signatures.md",
        "kb/incident_cases__incident_case_gps_jamming_vs_spoofing.md",
        "kb/incident_cases__incident_case_ugv_teleop_hijack.md",
    ],
    "llm": "GPS/GNSS 스푸핑 의심. EKF 수평위치 잔차가 급등하고 위성 수가 급감했으며, "
    "이는 실제 위성 신호 대신 가짜 GPS 신호를 주입하는 스푸핑의 특징과 일치한다.",
    "verdict": "true_positive → response (자동 RTB)",
}

TPL = r"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UAV AI SOC — 3D 폐루프 리플레이</title>
<style>
 *{margin:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,sans-serif}
 body{background:#0a0e1a;overflow:hidden;color:#e8eef7}
 #c{position:fixed;inset:0}
 .panel{position:fixed;background:rgba(12,18,33,.86);border:1px solid #1f3a5f;
   border-radius:10px;padding:14px 16px;backdrop-filter:blur(6px)}
 #title{top:16px;left:16px;font-size:15px;font-weight:700;letter-spacing:.3px}
 #title small{display:block;font-weight:400;color:#7d93b3;font-size:11px;margin-top:3px}
 #soc{top:16px;right:16px;width:340px;font-size:12px;line-height:1.6;opacity:.45;
   transition:opacity .4s,border-color .4s}
 #soc.on{opacity:1;border-color:#ff5a5a;box-shadow:0 0 24px rgba(255,90,90,.25)}
 #soc h3{font-size:13px;color:#ff7a7a;margin-bottom:6px}
 #soc .k{color:#7d93b3}
 #soc .rag{color:#6fc3ff;font-size:11px}
 #cap{bottom:90px;left:50%;transform:translateX(-50%);font-size:20px;font-weight:700;
   text-align:center;border:none;background:transparent;text-shadow:0 2px 12px #000;
   opacity:0;transition:opacity .3s}
 #ctrl{bottom:18px;left:50%;transform:translateX(-50%);display:flex;gap:12px;
   align-items:center;width:min(720px,92vw)}
 #ctrl button{background:#1f3a5f;color:#fff;border:none;border-radius:6px;
   padding:7px 14px;cursor:pointer;font-size:14px}
 #scrub{flex:1;accent-color:#6fc3ff}
 #clock{font-variant-numeric:tabular-nums;color:#9fb6d6;font-size:12px;min-width:70px}
 #legend{bottom:18px;left:16px;font-size:11px;line-height:1.7}
 .dot{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
</style></head><body>
<canvas id="c"></canvas>
<div id="title" class="panel">UAV AI SOC — 폐루프 데모 (실 비행 데이터)
 <small>정찰 → GNSS 스푸핑 공격 → 실시간 탐지 → 자동 RTB → 복귀</small></div>
<div id="soc" class="panel"><h3>🚨 SOC 탐지·대응 (6-에이전트)</h3>
 <div><span class="k">경보:</span> __T_TITLE__</div>
 <div><span class="k">탐지신호:</span> __T_SIG__</div>
 <div><span class="k">심각도:</span> <b style="color:#ff7a7a">__T_SEV__</b></div>
 <div><span class="k">RAG 근거:</span> __T_RAGN__건</div>
 <div class="rag">__T_RAG__</div>
 <div><span class="k">LLM 분석:</span> __T_LLM__</div>
 <div><span class="k">판정:</span> __T_VERD__</div></div>
<div id="cap" class="panel"></div>
<div id="legend" class="panel">
 <div><span class="dot" style="background:#37d67a"></span>정찰 비행</div>
 <div><span class="dot" style="background:#ff5a5a"></span>GNSS 스푸핑 공격</div>
 <div><span class="dot" style="background:#6fc3ff"></span>자동 복귀(RTB)</div></div>
<div id="ctrl" class="panel"><button id="play">⏸ 일시정지</button>
 <input id="scrub" type="range" min="0" max="1000" value="0">
 <span id="clock">0.0s</span><span id="clock2" style="color:#7d93b3"></span></div>
<script>__THREE__</script>
<script>__ORBIT__</script>
<script>
const DATA=__DATA__, SOC=__SOC__;
const S=DATA.samples, EV=DATA.events, T_END=S[S.length-1].t;
const ALT_X=2.2;                 // 고도 과장(가독)
const E=p=>(p.lon-DATA.home[1])*88000, N=p=>(p.lat-DATA.home[0])*111000;
// scene
const scene=new THREE.Scene(); scene.background=new THREE.Color(0x0a0e1a);
scene.fog=new THREE.Fog(0x0a0e1a,1400,3000);
const cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,1,8000);
cam.position.set(700,520,820);
const rnd=new THREE.WebGLRenderer({canvas:document.getElementById('c'),antialias:true});
rnd.setSize(innerWidth,innerHeight); rnd.setPixelRatio(devicePixelRatio);
const ctl=new THREE.OrbitControls(cam,rnd.domElement); ctl.target.set(0,120,-400); ctl.update();
scene.add(new THREE.AmbientLight(0x88aaff,.6));
const dl=new THREE.DirectionalLight(0xffffff,.8); dl.position.set(500,800,300); scene.add(dl);
// 지면 그리드
const grid=new THREE.GridHelper(2400,48,0x1f3a5f,0x14233d); scene.add(grid);
// HOME / 정찰지점 마커
function marker(x,z,col,h){const g=new THREE.Mesh(new THREE.ConeGeometry(18,h,4),
 new THREE.MeshBasicMaterial({color:col})); g.position.set(x,h/2,z); scene.add(g); return g;}
marker(0,0,0x37d67a,40);                                   // HOME
const patrolP=S.reduce((a,b)=>N(b)>N(a)?b:a,S[0]);
marker(E(patrolP),-N(patrolP),0xffb347,40);               // 정찰 최북단
// 경로(위상별 색)
function phaseCol(t){return t<EV.spoof?0x37d67a:(t<EV.rtb?0xff5a5a:0x6fc3ff);}
const pos=[],col=[];
for(const p of S){pos.push(E(p),p.alt*ALT_X,-N(p));const c=new THREE.Color(phaseCol(p.t));col.push(c.r,c.g,c.b);}
const lg=new THREE.BufferGeometry();
lg.setAttribute('position',new THREE.Float32BufferAttribute(pos,3));
lg.setAttribute('color',new THREE.Float32BufferAttribute(col,3));
scene.add(new THREE.Line(lg,new THREE.LineBasicMaterial({vertexColors:true,linewidth:2})));
// 드론
const drone=new THREE.Group();
drone.add(new THREE.Mesh(new THREE.SphereGeometry(12,16,16),new THREE.MeshStandardMaterial({color:0xffffff,emissive:0x224488})));
for(const[dx,dz]of[[18,18],[-18,18],[18,-18],[-18,-18]]){
 const r=new THREE.Mesh(new THREE.CylinderGeometry(10,10,3,16),new THREE.MeshStandardMaterial({color:0x6fc3ff,emissive:0x113355}));
 r.position.set(dx,2,dz); drone.add(r);}
scene.add(drone);
const halo=new THREE.Mesh(new THREE.RingGeometry(20,26,32),new THREE.MeshBasicMaterial({color:0xff5a5a,side:THREE.DoubleSide,transparent:true,opacity:0}));
halo.rotation.x=-Math.PI/2; drone.add(halo);
// 보간 위치
function sampleAt(t){let i=0;while(i<S.length-1&&S[i+1].t<t)i++;const a=S[i],b=S[Math.min(i+1,S.length-1)];
 const f=b.t>a.t?(t-a.t)/(b.t-a.t):0;
 return{x:E(a)+(E(b)-E(a))*f,y:(a.alt+(b.alt-a.alt)*f)*ALT_X,z:-(N(a)+(N(b)-N(a))*f),mode:b.mode};}
// 캡션/SOC 토글
const cap=document.getElementById('cap'),socEl=document.getElementById('soc');
function caption(t){
 let txt='',show=false;
 if(t>=EV.takeoff&&t<EV.patrol){txt='🛰️ 정찰 임무 개시 — 표적 상공으로 비행';show=true;}
 else if(t>=EV.patrol&&t<EV.spoof){txt='🛰️ 정찰 비행 중 (on-station)';show=true;}
 else if(t>=EV.spoof&&t<EV.spoof+6){txt='⚠️ GNSS 스푸핑 공격 — SOC 탐지: 심각도 h';show=true;}
 else if(t>=EV.rtb&&t<EV.rtb+6){txt='🛡️ SOC 자동 대응: RETURN-TO-LAUNCH 발령';show=true;}
 else if(t>EV.rtb+6&&t<T_END-3){txt='🛡️ INS 페일오버 + 자동 복귀 중';show=true;}
 else if(t>=T_END-3){txt='✅ 기체 복귀 — 자산 보호 완료';show=true;}
 cap.textContent=txt; cap.style.opacity=show?1:0;
 socEl.classList.toggle('on',t>=EV.spoof);
 halo.material.opacity=(t>=EV.spoof&&t<EV.rtb)?.8:0;
}
// 애니메이션
let play=true,head=0,last=performance.now(),SPEED=4;
const scrub=document.getElementById('scrub'),clk=document.getElementById('clock'),clk2=document.getElementById('clock2');
document.getElementById('play').onclick=function(){play=!play;this.textContent=play?'⏸ 일시정지':'▶ 재생';};
scrub.oninput=()=>{head=scrub.value/1000*T_END;};
function loop(now){requestAnimationFrame(loop);
 const dt=(now-last)/1000;last=now;
 if(play){head+=dt*SPEED;if(head>T_END)head=0;}
 const p=sampleAt(head); drone.position.set(p.x,p.y,p.z);
 scrub.value=head/T_END*1000; clk.textContent=head.toFixed(1)+'s';
 clk2.textContent=' · '+(p.mode||'');
 caption(head); ctl.update(); rnd.render(scene,cam);}
requestAnimationFrame(loop);
addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();rnd.setSize(innerWidth,innerHeight);});
</script></body></html>"""

html = (
    TPL.replace("__THREE__", three)
    .replace("__ORBIT__", orbit)
    .replace("__DATA__", json.dumps(traj))
    .replace("__SOC__", json.dumps(soc, ensure_ascii=False))
    .replace("__T_TITLE__", soc["title"])
    .replace("__T_SIG__", soc["signals"])
    .replace("__T_SEV__", soc["severity"])
    .replace("__T_RAGN__", str(len(soc["rag"])))
    .replace("__T_RAG__", "<br>".join("· " + r for r in soc["rag"]))
    .replace("__T_LLM__", soc["llm"])
    .replace("__T_VERD__", soc["verdict"])
)
out = f"{REC}/replay.html"
open(out, "w", encoding="utf-8").write(html)
print(f"생성: {out}  ({len(html)} bytes)")
