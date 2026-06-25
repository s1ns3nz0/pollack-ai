# 부록 E — 시나리오별·구조별 실제 에이전트 로그

> 각 시나리오를 각 구조로 실행하며 `soc.*` 로거가 남긴 실제 로그.
> 구조 차이가 로그에 드러난다(Router=investigation 부재, Supervisor=LLM 요약 생략,
> WizBlue=서브에이전트 병합 등). 라이브 LLM/RAG, 지연(ms)은 jitter 있음.

## S1 GNSS스푸핑 — GPS/GNSS 스푸핑에 의한 항법 탈취  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.751 · 2895.4ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-GPS-SPOOF-001 trusted=5 degraded=False ti=0 conf=0.75
ValidationAgent: validation: alert=KPI-TP-UAV-GPS-SPOOF-001 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GPS-SPOOF-001 playbook=PB-NAV-RTB-01
ReportAgent: report: alert=KPI-TP-UAV-GPS-SPOOF-001 severity=h verdict=true_positive
(investigation 요약) GPS/GNSS 스푸링 공격으로 인해 UAV의 GNSS-INS 위치 잔차와 HDOP가 급증했으며, 위성 수 및 신호 강도(C/N0) 변화가 비정상적으로 관찰되었다. 이로 인해 추정된 위치와 실제 위치 간 차이가 발생하여 항법 정밀도가 크게 저하되었고,
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.751 · 2224.4ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GPS-SPOOF-001 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GPS-SPOOF-001 playbook=PB-NAV-RTB-01
ReportAgent: report: alert=KPI-TP-UAV-GPS-SPOOF-001 severity=h verdict=true_positive
(investigation 요약) UAV가 GNSS 스푸핑 공격을 받고 있으며, 이는 HDOP와 위성 수의 비정상적인 변동 및 시각 점프를 통해 확인되었다. 위치 잔차(residual) 급증과 신호강도(C/N0) 이상 상승이 주요한 증거로 작용한다. GCS 통신 링크는 정상 상태를 유
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.751 · 2342.6ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-GPS-SPOOF-001 trusted=5 degraded=False ti=0 conf=0.75
ValidationAgent: validation: alert=KPI-TP-UAV-GPS-SPOOF-001 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GPS-SPOOF-001 playbook=PB-NAV-RTB-01
ReportAgent: report: alert=KPI-TP-UAV-GPS-SPOOF-001 severity=h verdict=true_positive
(investigation 요약) UAV가 GPS/GNSS 스푸핑 공격을 받았으며, 이는 GNSS-INS 위치 잔차 급증과 HDOP 비정상 변동으로 나타났다. 수신 신호강도(C/N0)의 이상적인 상승에도 불구하고, 시각(time) 점프가 관찰되어 정확한 탈취 징후를 확인하였다. 이러한
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.751 · 488.9ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GPS-SPOOF-001 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GPS-SPOOF-001 playbook=PB-NAV-RTB-01
ReportAgent: report: alert=KPI-TP-UAV-GPS-SPOOF-001 severity=h verdict=true_positive
(investigation 요약) GPS/GNSS 스푸핑에 의한 항법 탈취 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.751 · 1945.8ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GPS-SPOOF-001 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GPS-SPOOF-001 playbook=PB-NAV-RTB-01
ReportAgent: report: alert=KPI-TP-UAV-GPS-SPOOF-001 severity=h verdict=true_positive
(investigation 요약) UAV이 GNSS 스푸핑 공격을 받았습니다. 이는 GNSS-INS 잔차 급증 및 HDOP 비정상 변동, 수신 신호강도 상승 등의 현상을 통해 확인되었습니다. 이러한 증거들은 정확한 위치 정보에 대한 의심스러운 변경을 나타내며, GCS 통신 링크는 여전
```

## S2 C2하이재킹 — C2/RF 링크 재밍·하이재킹에 의한 통제권 상실  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.77 · 3000.8ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-C2-HIJACK-002 trusted=5 degraded=False ti=0 conf=0.77
ValidationAgent: validation: alert=KPI-TP-UAV-C2-HIJACK-002 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-C2-HIJACK-002 playbook=PB-C2-FAILSAFE-02
ReportAgent: report: alert=KPI-TP-UAV-C2-HIJACK-002 severity=h verdict=true_positive
(investigation 요약) C2 링크 재밍 후 비인가 소스에서의 명령 프레임 수신 및 기체 동작 불일치로 인해 C2 세션 하이재킹과 위조명령 주입 공격을 의심한다. 미발신 명령 수신과 시퀀스 번호 불연속은 명령 위조를 시사하며, 재밍 후 비정상 세션이 수립된 것이 핵심 근거이다
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.77 · 1848.4ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-C2-HIJACK-002 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-C2-HIJACK-002 playbook=PB-C2-FAILSAFE-02
ReportAgent: report: alert=KPI-TP-UAV-C2-HIJACK-002 severity=h verdict=true_positive
(investigation 요약) UAV의 C2 링크 재밍과 하이재킹으로 인해 통제권 상실이 발생했다. 지상국 미발신 명령 수신 및 시퀀스 번호 불연속 등이 확인되었다. 위조된 명령 주입을 통해 비인가 소스에서 명령 프레임이 감지되었으며, 이를 통해 C2 링크 하이재킹이 의심된다.
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.77 · 2091.0ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-C2-HIJACK-002 trusted=5 degraded=False ti=0 conf=0.77
ValidationAgent: validation: alert=KPI-TP-UAV-C2-HIJACK-002 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-C2-HIJACK-002 playbook=PB-C2-FAILSAFE-02
ReportAgent: report: alert=KPI-TP-UAV-C2-HIJACK-002 severity=h verdict=true_positive
(investigation 요약) C2/RF 링크 재밍 후 비인가 소스에서 위조된 명령 프레임 수신으로 UAV의 통제권이 탈취되었을 가능성이 높습니다. 미발신 명령과 시퀀스 번호 불연속은 명령 주입을 시사하며, 이는 단순 재밍보다 심각한 위협입니다. 대응책으로는 즉시 인증 검사를 강화
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.77 · 346.5ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-C2-HIJACK-002 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-C2-HIJACK-002 playbook=PB-C2-FAILSAFE-02
ReportAgent: report: alert=KPI-TP-UAV-C2-HIJACK-002 severity=h verdict=true_positive
(investigation 요약) C2/RF 링크 재밍·하이재킹에 의한 통제권 상실 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.77 · 2141.1ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-C2-HIJACK-002 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-C2-HIJACK-002 playbook=PB-C2-FAILSAFE-02
ReportAgent: report: alert=KPI-TP-UAV-C2-HIJACK-002 severity=h verdict=true_positive
(investigation 요약) C2 링크 재밍 후 비정상 세션이 수립되며, 지상국 미발신 명령이 드론에 전달되었다. 이는 명령 시퀀스 번호의 불연속성과 함께 C2 링크 하이재킹 및 위조명령 주입을 의심하게 한다. 대응책으로는 인증 서명 검사를 강제하고 미인증 명령은 폐기하며, 통신
```

## S3 SATCOM MITM — SATCOM 데이터링크 중간자 공격에 의한 데이터 변조·정보유출  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.794 · 2619.2ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SATCOM-MITM-003 trusted=3 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-MITM-003 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-MITM-003 playbook=PB-LINK-INTEG-03
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-MITM-003 severity=m verdict=true_positive
(investigation 요약) SATCOM 데이터링크에서 중간자 공격으로 인해 링크 지연과 메시지 무결성 검증 실패가 발생하여 텔레메트리 스트림의 정보 유출이 의심된다. 체크섬 불일치와 링크 경로 이상이 확인되어 단순 장애보다 중간자 공격 가능성이 높다. 위협은 가용성보다 무결성과
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.794 · 1508.5ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-MITM-003 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-MITM-003 playbook=PB-LINK-INTEG-03
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-MITM-003 severity=m verdict=true_positive
(investigation 요약) SATCOM 데이터링크에서 중간자(MITM) 공격으로 인한 데이터 변조와 정보유출이 의심된다. 링크 지연, MAC 실패율 증가 및 체크섬 불일치가 확인되었으며, 이는 단순 통신장애가 아닌 무결성 위협을 시사한다.
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.794 · 1573.8ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SATCOM-MITM-003 trusted=3 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-MITM-003 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-MITM-003 playbook=PB-LINK-INTEG-03
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-MITM-003 severity=m verdict=true_positive
(investigation 요약) SATCOM 데이터링크 중간자(MITM) 공격으로 인해 링크 지연과 메시지 무결성 검증 실패율 증가, 체크섬 불일치가 발생하여 페이로드 및 텔레메트리 스트림의 데이터 변조와 정보유출이 의심된다.
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.794 · 289.7ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-MITM-003 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-MITM-003 playbook=PB-LINK-INTEG-03
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-MITM-003 severity=m verdict=true_positive
(investigation 요약) SATCOM 데이터링크 중간자 공격에 의한 데이터 변조·정보유출 상관분석: 신뢰 사례 3건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.794 · 2079.3ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-MITM-003 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-MITM-003 playbook=PB-LINK-INTEG-03
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-MITM-003 severity=m verdict=true_positive
(investigation 요약) SATCOM 데이터링크에서 중간자 공격으로 인해 메시지 무결성 검증 실패와 체크섬 불일치가 발생하여 텔레메트리 스트림의 기밀성과 무결성이 위협받고 있다. 링크 지연 및 경로 이상이 동반되면서 단순 장애보다 공격 가능성이 높아 심각도는 중간(m)으로 분
```

## S4 펌웨어공급망 — 펌웨어/공급망 변조에 의한 비행제어기 무결성 손상  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.778 · 2643.3ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-FW-SUPPLY-004 trusted=3 degraded=False ti=0 conf=0.78
ValidationAgent: validation: alert=KPI-TP-UAV-FW-SUPPLY-004 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-FW-SUPPLY-004 playbook=PB-FW-INTEG-04
ReportAgent: report: alert=KPI-TP-UAV-FW-SUPPLY-004 severity=h verdict=true_positive
(investigation 요약) 비행제어기 펌웨어 해시 검증 실패와 SBOM 미등록 컴포넌트 발견으로 인해 펌웨어 공급망 변조가 의심된다. 비인가 펌웨어 버전과 예상치 못한 모듈 로드는 무결성을 위반하며, 이는 잠복형 제어 로직 변조를 시사한다. 기준 심각도 h로 분류되며, 대량의 
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.778 · 1810.4ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-FW-SUPPLY-004 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-FW-SUPPLY-004 playbook=PB-FW-INTEG-04
ReportAgent: report: alert=KPI-TP-UAV-FW-SUPPLY-004 severity=h verdict=true_positive
(investigation 요약) 비행제어기 펌웨어 해시 검증 실패와 비인가 컴포넌트 탐지로 인해 펌웨어 공급망 변조 공격이 의심된다. 무결성 위협으로 함대 단위의 중대한 위험을 초래할 수 있으며, 예상치 못게 제어 로직 변조 또는 백도어 발현 가능성이 있다.
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.778 · 2244.6ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-FW-SUPPLY-004 trusted=3 degraded=False ti=0 conf=0.78
ValidationAgent: validation: alert=KPI-TP-UAV-FW-SUPPLY-004 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-FW-SUPPLY-004 playbook=PB-FW-INTEG-04
ReportAgent: report: alert=KPI-TP-UAV-FW-SUPPLY-004 severity=h verdict=true_positive
(investigation 요약) 비행제어기 펌웨어 해시 검증 실패와 SBOM 미등록 컴포넌트 발견으로 부품 공급망 변조가 의심된다. 비정상적인 부팅 시퀀스와 예상치 못한 모듈 로드는 추가적으로 펌웨어 무결성 손상을 확인한다. 이러한 증거들은 심각도 h의 위협을 나타내며, 잠복형 변조
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.778 · 299.8ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-FW-SUPPLY-004 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-FW-SUPPLY-004 playbook=PB-FW-INTEG-04
ReportAgent: report: alert=KPI-TP-UAV-FW-SUPPLY-004 severity=h verdict=true_positive
(investigation 요약) 펌웨어/공급망 변조에 의한 비행제어기 무결성 손상 상관분석: 신뢰 사례 3건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.778 · 1874.0ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-FW-SUPPLY-004 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-FW-SUPPLY-004 playbook=PB-FW-INTEG-04
ReportAgent: report: alert=KPI-TP-UAV-FW-SUPPLY-004 severity=h verdict=true_positive
(investigation 요약) 비행제어기 펌웨어 해시 검증 실패와 비인가 컴포넌트 발견으로 인해 부품 공급망에서의 변조 의심이 제기된다. 무결성 위협과 함대 단위 위험을 시사하며, 예상치 못한 모듈 로드 및 외부 연결 시도 등 증거가 추가적 위협 가능성을 암시한다.
```

## S5 RAG포이즈닝 — RAG 포이즈닝·프롬프트 인젝션에 의한 SOC 에이전트 심각도 다운그레이드  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.774 · 3157.4ms
```
InvestigationAgent: investigation: alert=KPI-TP-AI-RAG-POISON-005 trusted=5 degraded=False ti=0 conf=0.77
ValidationAgent: validation: alert=KPI-TP-AI-RAG-POISON-005 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-RAG-POISON-005 playbook=PB-AISOC-GUARD-05
ReportAgent: report: alert=KPI-TP-AI-RAG-POISON-005 severity=h verdict=true_positive
(investigation 요약) SOC 에이전트가 RAG 포이즈닝과 프롬프트 인젝션에 의한 심각도 다운그레이드로 고위험 경보를 저평가하게 만드는 메타 위협이 발생했다. 주요 증거로 정책엔진의 등급과 에이전트 판정 간 괴리, 미신뢰 출처 컨텍스트가 있다. 이를 대응하기 위해 검색 컨텍
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.774 · 1870.8ms
```
ValidationAgent: validation: alert=KPI-TP-AI-RAG-POISON-005 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-RAG-POISON-005 playbook=PB-AISOC-GUARD-05
ReportAgent: report: alert=KPI-TP-AI-RAG-POISON-005 severity=h verdict=true_positive
(investigation 요약) SOC 에이전트가 RAG 포이즈닝 및 프롬프트 인젝션에 의해 고위험 경보를 저위험으로 잘못 판정하고 있다. 주요 증거는 미신뢰 출처의 컨텍스트 사용과 정책엔진과의 심각도 괴리다. 방어 AI 자체가 공격 대상이므로 즉시 인간의 판단을 받아 검증해야 한다
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.774 · 1982.6ms
```
InvestigationAgent: investigation: alert=KPI-TP-AI-RAG-POISON-005 trusted=5 degraded=False ti=0 conf=0.77
ValidationAgent: validation: alert=KPI-TP-AI-RAG-POISON-005 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-RAG-POISON-005 playbook=PB-AISOC-GUARD-05
ReportAgent: report: alert=KPI-TP-AI-RAG-POISON-005 severity=h verdict=true_positive
(investigation 요약) SOC 에이전트가 RAG 포이즈닝으로 인해 고위험 경보를 저위험으로 오판정한 것이 의심된다. 주요 근거는 미신뢰 출처의 컨텍스트 검색과 정책 엔진 기대 등급과 에이전트 판정 간 괴리이다. 이 메타 위협은 UAV 공격 탐지와 대응을 무력화할 수 있다.
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.774 · 353.9ms
```
ValidationAgent: validation: alert=KPI-TP-AI-RAG-POISON-005 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-RAG-POISON-005 playbook=PB-AISOC-GUARD-05
ReportAgent: report: alert=KPI-TP-AI-RAG-POISON-005 severity=h verdict=true_positive
(investigation 요약) RAG 포이즈닝·프롬프트 인젝션에 의한 SOC 에이전트 심각도 다운그레이드 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.774 · 2381.1ms
```
ValidationAgent: validation: alert=KPI-TP-AI-RAG-POISON-005 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-RAG-POISON-005 playbook=PB-AISOC-GUARD-05
ReportAgent: report: alert=KPI-TP-AI-RAG-POISON-005 severity=h verdict=true_positive
(investigation 요약) SOC 에이전트가 RAG 포이즈닝 또는 프롬프트 인젝션으로 인해 고위험 경보를 저평가하여 심각도를 다운그레이드 시키고 있다. 이로 인해 정책 엔진과의 괴리 현상 및 LLM-as-Judge 점수 급락이 발생하였다. 대응策としては、搜索上下文的出处/签名不符
```

## S6 GCS횡적확산 — 지상통제소(GCS) 침해에 의한 임무 재지정·함대 횡적 확산  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.775 · 2716.2ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-GCS-LATERAL-006 trusted=5 degraded=False ti=0 conf=0.78
ValidationAgent: validation: alert=KPI-TP-UAV-GCS-LATERAL-006 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GCS-LATERAL-006 playbook=PB-GCS-CONTAIN-06
ReportAgent: report: alert=KPI-TP-UAV-GCS-LATERAL-006 severity=h verdict=true_positive
(investigation 요약) GCS가 침해되어 비정상적인 로그인과 다수의 드론이 동시에 임무 재지정되는 현상이 발생했다. 또한, GCS에서 내부망으로 비정상적 횡적 연결이 이루어져 권한 상승 또는 신규 계정 생성도 확인되었다. 이러한 증상은 공격자가 GCS를 발판 삼아 함대 전체
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.775 · 2159.2ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GCS-LATERAL-006 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GCS-LATERAL-006 playbook=PB-GCS-CONTAIN-06
ReportAgent: report: alert=KPI-TP-UAV-GCS-LATERAL-006 severity=h verdict=true_positive
(investigation 요약) 공격자가 GCS를 통해 침입하여 다수 드론의 임무를 재지정하고, 내부 네트워크로 횡적 확산을 시도한 것으로 보인다. 주요 근거는 비정상적인 시간과 위치에서의 로그인 및 단시간 내 다수 드론의 동시 임무 변경이다. 이를 통해 공격자는 위조된 명령을 발동
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.775 · 2146.7ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-GCS-LATERAL-006 trusted=5 degraded=False ti=0 conf=0.78
ValidationAgent: validation: alert=KPI-TP-UAV-GCS-LATERAL-006 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GCS-LATERAL-006 playbook=PB-GCS-CONTAIN-06
ReportAgent: report: alert=KPI-TP-UAV-GCS-LATERAL-006 severity=h verdict=true_positive
(investigation 요약) 공격자가 GCS를 침해하여 다수 무인기의 임무를 재지정하고, 내부 네트워크로 횡적으로 확산하는 정황이 있다. 비정상 시간/위치에서 로그인과 권한 상승, 다중 기체 동시 임무 재지정 등이 확인되었다. 이를 근거로 공격자가 유효 계정을 이용해 GCS를 통
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.775 · 352.0ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GCS-LATERAL-006 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GCS-LATERAL-006 playbook=PB-GCS-CONTAIN-06
ReportAgent: report: alert=KPI-TP-UAV-GCS-LATERAL-006 severity=h verdict=true_positive
(investigation 요약) 지상통제소(GCS) 침해에 의한 임무 재지정·함대 횡적 확산 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.775 · 1937.9ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-GCS-LATERAL-006 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-GCS-LATERAL-006 playbook=PB-GCS-CONTAIN-06
ReportAgent: report: alert=KPI-TP-UAV-GCS-LATERAL-006 severity=h verdict=true_positive
(investigation 요약) 공격자가 GCS를 침해하여 다수의 무인기 임무를 위조 재지정하고, 내부망으로 횡적 확산을 시도하고 있다. 비정상 로그인과 단시간에 발생한 다수 기체의 동시 임무 재지정이 확인되었다. GCS 침해로 인한 함대 전체 영향을 최소화하기 위해 즉시 대응 조치
```

## S7 UGV탈취 — UGV 원격조종 탈취 및 자율주행 센서 스푸핑(노획 시 자격증명 유출)  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.793 · 2668.4ms
```
InvestigationAgent: investigation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UGV-TELEOP-HIJACK-007 playbook=PB-UGV-CONTAIN-07
ReportAgent: report: alert=KPI-TP-UGV-TELEOP-HIJACK-007 severity=h verdict=true_positive
(investigation 요약) UGV 원격조종이 탈취되어 자율주행 센서가 스된 것으로 보인다. LiDAR와 카메라 인식 신뢰도 급락 및 주행계획 모순, 비정상 정지/경로이탈 후 통신 두절 현상과 노획 증거(가속도/기울기 이상)를 통해 확인 가능하다. 탈취된 자격증명의 다른 시스템에
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.793 · 1887.8ms
```
ValidationAgent: validation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UGV-TELEOP-HIJACK-007 playbook=PB-UGV-CONTAIN-07
ReportAgent: report: alert=KPI-TP-UGV-TELEOP-HIJACK-007 severity=h verdict=true_positive
(investigation 요약) UGV 원격조종이 탈취되었고 자율주행 센서가 스푸핑 되어 인식 신뢰도와 주행 계획에 문제가 발생했습니다. 노획된 자격증명을 다른 시스템에서 재사용하려는 행위가 확인되어 추가 위험이 제기됩니다. 이로 인해 UGV의 통신이 두절되고 비정상적으로 정지하거나
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.793 · 1726.6ms
```
InvestigationAgent: investigation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UGV-TELEOP-HIJACK-007 playbook=PB-UGV-CONTAIN-07
ReportAgent: report: alert=KPI-TP-UGV-TELEOP-HIJACK-007 severity=h verdict=true_positive
(investigation 요약) UGV 원격조종 시스템이 탈취되었으며, 자율주행 센서도 스푸핑 공격을 받았다. 이로 인해 온보드 자격증명이 유출되어 다른 시스템에서도 재사용이 이루어진 것으로 보인다. 경고 수준은 심각도 H로 분류되어 즉시 조치가 필요하다.
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.793 · 317.5ms
```
ValidationAgent: validation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UGV-TELEOP-HIJACK-007 playbook=PB-UGV-CONTAIN-07
ReportAgent: report: alert=KPI-TP-UGV-TELEOP-HIJACK-007 severity=h verdict=true_positive
(investigation 요약) UGV 원격조종 탈취 및 자율주행 센서 스푸핑(노획 시 자격증명 유출) 상관분석: 신뢰 사례 4건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.793 · 1940.9ms
```
ValidationAgent: validation: alert=KPI-TP-UGV-TELEOP-HIJACK-007 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UGV-TELEOP-HIJACK-007 playbook=PB-UGV-CONTAIN-07
ReportAgent: report: alert=KPI-TP-UGV-TELEOP-HIJACK-007 severity=h verdict=true_positive
(investigation 요약) UGV 원격조종이 탈취되고 자율주행 센서가 스푸핑되어 노획된 자격증명이 다른 시스템에서 재사용되는 경로이탈 및 통신 중단 현상 발생. 이는 MITRE ATT&CK T0814, T0855, T0831 등으로 분류되며, 즉각적인 대응과 자격증명 회전이 요
```

## S8 온보드AI — 온보드 표적인식 AI에 대한 적대적 공격(적대적 패치·디코이·센서 dazzling)  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.786 · 2432.2ms
```
InvestigationAgent: investigation: alert=KPI-TP-AI-ONBOARD-EVADE-008 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-AI-ONBOARD-EVADE-008 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-ONBOARD-EVADE-008 playbook=PB-ONBOARDAI-08
ReportAgent: report: alert=KPI-TP-AI-ONBOARD-EVADE-008 severity=m verdict=true_positive
(investigation 요약) 온보드 표적인식 AI에 대한 적대적 공격(적대적 패치, 디코이, 센서 dazzling)이 의심된다. 탐지 신뢰도 분포와 다중센서 불일치, 지형매칭 잔차 급증 등이 확인되었다. 이로 인해 표적 감지 기능의 신뢰성 저하와 경보 시스템 오작동이 발생하였다.
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.786 · 1678.5ms
```
ValidationAgent: validation: alert=KPI-TP-AI-ONBOARD-EVADE-008 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-ONBOARD-EVADE-008 playbook=PB-ONBOARDAI-08
ReportAgent: report: alert=KPI-TP-AI-ONBOARD-EVADE-008 severity=m verdict=true_positive
(investigation 요약) 온보드 표적인식 AI에 대한 적대적 공격이 의심된다. 탐지 신뢰도 분포 급변, 다중 센서 간 표적 불일치, 디코이 패턴 등이 확인되었다. MITRE ATLAS에서 AML.T0015와 AML.T0043과 연관 지어 분석 중이다.
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.786 · 1668.3ms
```
InvestigationAgent: investigation: alert=KPI-TP-AI-ONBOARD-EVADE-008 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-AI-ONBOARD-EVADE-008 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-ONBOARD-EVADE-008 playbook=PB-ONBOARDAI-08
ReportAgent: report: alert=KPI-TP-AI-ONBOARD-EVADE-008 severity=m verdict=true_positive
(investigation 요약) 온보드 표적인식 AI에 대한 적대적 공격이 의심된다. 탐지 신호 분석 결과, 다중 센서 간의 불일치와 디코이 패턴 등이 확인되었다. 이로 인해 경보 신뢰도가 저하되어 SOC의 판단이 희박해진 것으로 보인다.
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.786 · 336.0ms
```
ValidationAgent: validation: alert=KPI-TP-AI-ONBOARD-EVADE-008 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-ONBOARD-EVADE-008 playbook=PB-ONBOARDAI-08
ReportAgent: report: alert=KPI-TP-AI-ONBOARD-EVADE-008 severity=m verdict=true_positive
(investigation 요약) 온보드 표적인식 AI에 대한 적대적 공격(적대적 패치·디코이·센서 dazzling) 상관분석: 신뢰 사례 4건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 m · conf 0.786 · 1627.5ms
```
ValidationAgent: validation: alert=KPI-TP-AI-ONBOARD-EVADE-008 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-AI-ONBOARD-EVADE-008 playbook=PB-ONBOARDAI-08
ReportAgent: report: alert=KPI-TP-AI-ONBOARD-EVADE-008 severity=m verdict=true_positive
(investigation 요약) 온보드 표적인식 AI에 대한 적대적 공격이 의심된다. 탐지 신뢰도 분포 급변 및 다중 센서 간 표적 불일치, 디코이 동시 출현 등으로 확인되었다. 지형매칭 잔차와 waypoint provenance 오류 또한 이를 뒷받침한다.
```

## S9 군집포화 — 군집 포화 공격에 의한 다축 동시침해 및 SOC 탐지·인지 과부하  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.785 · 2516.6ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SWARM-SATURATION-009 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UAV-SWARM-SATURATION-009 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SWARM-SATURATION-009 playbook=PB-SWARM-AGGREGATE-09
ReportAgent: report: alert=KPI-TP-UAV-SWARM-SATURATION-009 severity=h verdict=true_positive
(investigation 요약) 군집 포화 공격으로 인한 다축 동시 침해와 SOC 탐지 과부하가 의심된다. 이는 단시간 내 동일 유형 경보 급증과 트랙 클러스터의 동시 발생, 운용자 처리 지연 등을 통해 확인되었다. 이러한 상황은 핵심 경보 누락을 초래할 위험이 있으며, 자산 AI_
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.785 · 2093.1ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SWARM-SATURATION-009 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SWARM-SATURATION-009 playbook=PB-SWARM-AGGREGATE-09
ReportAgent: report: alert=KPI-TP-UAV-SWARM-SATURATION-009 severity=h verdict=true_positive
(investigation 요약) 군집 포화 공격으로 인해 다축 동시 침해 및 SOC 탐지 과부하가 발생한 것으로 보인다. 이로 인해 경보 처리 지연과 신뢰도 저하가 동반되며, 핵심 경보 누락 위험이 있다. 이를 통해 시스템을 마비시키고 심각도를 다운그레이드시켜 탐지와 대응 능력을 무
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.785 · 2041.3ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SWARM-SATURATION-009 trusted=4 degraded=False ti=0 conf=0.79
ValidationAgent: validation: alert=KPI-TP-UAV-SWARM-SATURATION-009 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SWARM-SATURATION-009 playbook=PB-SWARM-AGGREGATE-09
ReportAgent: report: alert=KPI-TP-UAV-SWARM-SATURATION-009 severity=h verdict=true_positive
(investigation 요약) 군집 포화 공격으로 인해 다축 동시 침해가 발생하고 SOC 탐지 과부하 상태에 빠졌다. 이로 인해 경보 처리 지연과 큐 적체 현상이 나타났으며, 디코이와 실표적 분류 신뢰도 또한 저하되었다. 이는 RAG 포이즈닝을 통해 고위험 경보가 하향평가되어 탐지
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.785 · 319.6ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SWARM-SATURATION-009 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SWARM-SATURATION-009 playbook=PB-SWARM-AGGREGATE-09
ReportAgent: report: alert=KPI-TP-UAV-SWARM-SATURATION-009 severity=h verdict=true_positive
(investigation 요약) 군집 포화 공격에 의한 다축 동시침해 및 SOC 탐지·인지 과부하 상관분석: 신뢰 사례 4건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.785 · 1607.4ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SWARM-SATURATION-009 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SWARM-SATURATION-009 playbook=PB-SWARM-AGGREGATE-09
ReportAgent: report: alert=KPI-TP-UAV-SWARM-SATURATION-009 severity=h verdict=true_positive
(investigation 요약) 군집 포화 공격으로 인한 다축 동시 침해가 발생하여 SOC 탐지 및 인지 과부하 상태에 빠졌다. 이는 단시간 내 동일 유형 경보 급증과 신뢰도 저하를 동반하며, 이를 통해 핵심 경보 누락을 시도하고 있다.
```

## S10 SATCOM무력화 — SATCOM 단말/관리망 무력화에 의한 UAV/UGV 운용망 고립  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.797 · 2813.1ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 trusted=5 degraded=False ti=0 conf=0.80
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 playbook=PB-SATCOM-FAILOVER-10
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 severity=h verdict=true_positive
(investigation 요약) 다수의 SATCOM 단말 동시 접속 실패와 관리 채널 오류 급증 등으로 UAV/UGV 운용망 무력화 공격이 의심된다. 이는 펌웨어 및 설정 무결성 이상과 함께 대량 장애를 유발하며, MITRE ATT&CK의 Denial of Service와 Syste
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.797 · 2153.6ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 playbook=PB-SATCOM-FAILOVER-10
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 severity=h verdict=true_positive
(investigation 요약) 다수의 SATCOM 단말이 동시 접속 실패와 펌웨어/설정 무결성 이상을 보여, UAV/UGV 운용망 고립 공격 가능성이 높다. 관리 채널 오류와 비인가 변경 증가로 볼 때, T2 중요 자산에 대한 DoS 및 데이터 손상 공격이 진행되고 있다. 이는 M
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.797 · 1969.0ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 trusted=5 degraded=False ti=0 conf=0.80
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 playbook=PB-SATCOM-FAILOVER-10
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 severity=h verdict=true_positive
(investigation 요약) 다수의 SATCOM 단말이 동시 접속 실패하고, 펌웨어/설정 무결성 이상 및 관리 채널 비인가 변경이 발생하여 UAV/UGV 운용망 고립을 시도하는 공격이 의심된다. 이는 MITRE ATT&CK Denial of Service(T0814)와 Syste
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.797 · 318.6ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 playbook=PB-SATCOM-FAILOVER-10
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 severity=h verdict=true_positive
(investigation 요약) SATCOM 단말/관리망 무력화에 의한 UAV/UGV 운용망 고립 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.797 · 1876.4ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 playbook=PB-SATCOM-FAILOVER-10
ReportAgent: report: alert=KPI-TP-UAV-SATCOM-TAKEDOWN-010 severity=h verdict=true_positive
(investigation 요약) 다수 SATCOM 단말 동시 접속 실패와 관리 채널 비인가 변경 급증으로 UAV/UGV 운용망 고립 공격이 의심된다. 대량 단말 장애 및 무결성 이상은 일반적인 장비 문제를 넘어 보안 위협을 암시한다. 이를 근거로 기준 심각도 **h**를 적용하고 즉
```

## S11 모바일GCS — 전술 태블릿/모바일 GCS 앱 침해에 의한 임무데이터 유출 및 위조임무 주입  (정탐)

**[baseline]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.74 · 2219.0ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-MOBILE-GCS-011 trusted=2 degraded=False ti=0 conf=0.74
ValidationAgent: validation: alert=KPI-TP-UAV-MOBILE-GCS-011 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-MOBILE-GCS-011 playbook=PB-MOBILEGCS-CONTAIN-11
ReportAgent: report: alert=KPI-TP-UAV-MOBILE-GCS-011 severity=h verdict=true_positive
(investigation 요약) 전술 태블릿/모바일 GCS 앱 침해로 인한 임무데이터 유출 및 위조임무 주입이 의심된다. 비인가 앱 설치, 임무파일의 비정상 접근, 외부 통신 증가 등의 정황이 확인되었다. 이로 인해 GCS 세션 토큰 재사용과 위치/시간에 따른 접속 패턴 변경이 발생
```

**[parallel]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.74 · 1841.0ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-MOBILE-GCS-011 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-MOBILE-GCS-011 playbook=PB-MOBILEGCS-CONTAIN-11
ReportAgent: report: alert=KPI-TP-UAV-MOBILE-GCS-011 severity=h verdict=true_positive
(investigation 요약) 전술 태블릿/모바일 GCS 앱 침해로 인한 임무데이터 유출 및 위조임무 주입이 의심된다. 비인가 앱 설치, 임무파일 접근 이상, 외부 통신 증가, 세션 토큰 재사용, 위치 시간 이상 접속 등으로 확인되었다. 자산 GCS는 심각도 h로 평가된다.
```

**[router]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.74 · 1854.7ms
```
InvestigationAgent: investigation: alert=KPI-TP-UAV-MOBILE-GCS-011 trusted=2 degraded=False ti=0 conf=0.74
ValidationAgent: validation: alert=KPI-TP-UAV-MOBILE-GCS-011 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-MOBILE-GCS-011 playbook=PB-MOBILEGCS-CONTAIN-11
ReportAgent: report: alert=KPI-TP-UAV-MOBILE-GCS-011 severity=h verdict=true_positive
(investigation 요약) 전술 태블릿/모바일 GCS 앱이 침해되어 임무데이터 유출과 위조임무 주입이 발생한 것으로 보인다. 비인가 앱 설치, 임무파일 접근 이상, 외부 통신 증가 등의 징후가 확인되었다. MITRE ATT&CK 기준으로 T0822 External Remote 
```

**[supervisor]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.74 · 297.9ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-MOBILE-GCS-011 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-MOBILE-GCS-011 playbook=PB-MOBILEGCS-CONTAIN-11
ReportAgent: report: alert=KPI-TP-UAV-MOBILE-GCS-011 severity=h verdict=true_positive
(investigation 요약) 전술 태블릿/모바일 GCS 앱 침해에 의한 임무데이터 유출 및 위조임무 주입 상관분석: 신뢰 사례 2건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → response → report` · 판정 true_positive · 심각도 h · conf 0.74 · 2094.7ms
```
ValidationAgent: validation: alert=KPI-TP-UAV-MOBILE-GCS-011 verdict=true_positive
ResponseAgent: response: alert=KPI-TP-UAV-MOBILE-GCS-011 playbook=PB-MOBILEGCS-CONTAIN-11
ReportAgent: report: alert=KPI-TP-UAV-MOBILE-GCS-011 severity=h verdict=true_positive
(investigation 요약) 전술 태블릿/모바일 GCS 앱이 침해되어 임무 데이터가 유출 및 위조임무 주입이 발생한 것으로 의심된다. 비인가 앱 설치, 임무파일 접근, 외부 통신 증가와 같은 정황들이 이를 뒷받침한다. C2 링크 하이재킹으로 인해 세션 토큰이 재사용되고, 기체 동
```

## 오탐 GPS-DEGRADE-URBAN — GPS 정확도 경미 저하(도심 협곡)  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.731 · 2930.9ms
```
InvestigationAgent: investigation: alert=KPI-FP-GPS-DEGRADE-URBAN trusted=5 degraded=False ti=0 conf=0.73
ValidationAgent: validation: alert=KPI-FP-GPS-DEGRADE-URBAN verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-GPS-DEGRADE-URBAN rule=unknown.yml
ReportAgent: report: alert=KPI-FP-GPS-DEGRADE-URBAN severity=l verdict=false_positive
(investigation 요약) 경보는 GPS 정확도의 경미한 저하를 나타내며, 위성 수가 14에서 9로 감소했다. 이는 GPS 스푸핑 공격이나 재밍 중 하나일 가능성이 있으며, GCS 통신 링크 상태가 정상이므로 네트워크 장애와 구분해야 한다. 현재 데이터만으로는 스푸핑과 재밍을 
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.731 · 2179.2ms
```
ValidationAgent: validation: alert=KPI-FP-GPS-DEGRADE-URBAN verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-GPS-DEGRADE-URBAN rule=unknown.yml
ReportAgent: report: alert=KPI-FP-GPS-DEGRADE-URBAN severity=l verdict=false_positive
(investigation 요약) 경보는 위성 수의 경미한 감소를 나타내나, 정확도 저하와 조종 장비(GCS) 연결 상태에 이상이 없는 점을 고려할 때 GPS 스푸핑 공격의 가능성이 있다. 주요 증거로 위성을 이용하는 개체수가 예상치보다 줄어든 것이 확인되었다. 이는 정확도가 떨어지면
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 l · conf None · 0.2ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-GPS-DEGRADE-URBAN rule=unknown.yml
ReportAgent: report: alert=KPI-FP-GPS-DEGRADE-URBAN severity=l verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.731 · 490.5ms
```
ValidationAgent: validation: alert=KPI-FP-GPS-DEGRADE-URBAN verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-GPS-DEGRADE-URBAN rule=unknown.yml
ReportAgent: report: alert=KPI-FP-GPS-DEGRADE-URBAN severity=l verdict=false_positive
(investigation 요약) GPS 정확도 경미 저하(도심 협곡) 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.731 · 2533.2ms
```
ValidationAgent: validation: alert=KPI-FP-GPS-DEGRADE-URBAN verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-GPS-DEGRADE-URBAN rule=unknown.yml
ReportAgent: report: alert=KPI-FP-GPS-DEGRADE-URBAN severity=l verdict=false_positive
(investigation 요약) 경보는 위성 수의 감소와 관련이 있지만, 정확도 저하가 경미하고 다른 지표들은 정상 범위 내에 있어 명확한 GPS 재밍이나 스푸핑 공격으로 보기는 어렵다. 그러나 위성이 9개로 줄어든 점은 정상 범위(평균 13.616, 최대 14)에서 하락한 것을 반
```

## 오탐 FW-SIGNED-UPDATE — 정상 펌웨어 업데이트(서명·SBOM 일치)  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.753 · 2040.8ms
```
InvestigationAgent: investigation: alert=KPI-FP-FW-SIGNED-UPDATE trusted=3 degraded=False ti=0 conf=0.75
ValidationAgent: validation: alert=KPI-FP-FW-SIGNED-UPDATE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-FW-SIGNED-UPDATE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-FW-SIGNED-UPDATE severity=i verdict=false_positive
(investigation 요약) 비행제어기 펌웨어 해시와 SBOM 일치 신호는 외관상 정상 업데이트 같지만, 서명 유효성과 SBOM 등록만으로는 불충분하며 비인가 컴포넌트의 존재를 시사한다. 이는 공급망 변조 공격을 의심하게 한다.
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.753 · 2047.8ms
```
ValidationAgent: validation: alert=KPI-FP-FW-SIGNED-UPDATE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-FW-SIGNED-UPDATE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-FW-SIGNED-UPDATE severity=i verdict=false_positive
(investigation 요약) 비행제어기 펌웨어 해시와 서명이 변경되었음에도 불구하고 SBOM에 등록된 컴포넌트와 일치하는 것으로 나타나 정상 업데이트로 판단되는 경보가 발생했다. 그러나 실제 이는 부품 공급망에서의 펌웨어 변조를 시사하며, 서명/해시 불일치와 SBOM 미등록 컴포
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 i · conf None · 0.2ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-FW-SIGNED-UPDATE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-FW-SIGNED-UPDATE severity=i verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.753 · 249.5ms
```
ValidationAgent: validation: alert=KPI-FP-FW-SIGNED-UPDATE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-FW-SIGNED-UPDATE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-FW-SIGNED-UPDATE severity=i verdict=false_positive
(investigation 요약) 정상 펌웨어 업데이트(서명·SBOM 일치) 상관분석: 신뢰 사례 3건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.753 · 1913.9ms
```
ValidationAgent: validation: alert=KPI-FP-FW-SIGNED-UPDATE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-FW-SIGNED-UPDATE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-FW-SIGNED-UPDATE severity=i verdict=false_positive
(investigation 요약) 비행제어기 펌웨어 해시와 SBOM 불일치 및 비인가 컴포넌트 발견으로 부품 공급망에서의 변조 가능성이 제기된다. 이는 무결성 위협을 야기하며, 임의 시점에 제어 로직이 변조될 수 있는 심각한 위험이다. 서명 검증 과정에서 발생한 이상 징후가 주요 근거
```

## 오탐 C2-RSSI-WEATHER — 기상에 의한 C2 RSSI 일시 저하  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.734 · 2363.4ms
```
InvestigationAgent: investigation: alert=KPI-FP-C2-RSSI-WEATHER trusted=4 degraded=False ti=0 conf=0.73
ValidationAgent: validation: alert=KPI-FP-C2-RSSI-WEATHER verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-C2-RSSI-WEATHER rule=unknown.yml
ReportAgent: report: alert=KPI-FP-C2-RSSI-WEATHER severity=l verdict=false_positive
(investigation 요약) C2 링크 하이재킹 및 명령 주입 공격이 의심된다. 기체가 지상국(GCS) 미발신 명령을 수신했으며, C2 RSSI 일시 저하 후 비정상 세션이 수립되었다. MITRE ATT&CK T0814 Deni와 관련된 이 의심 경보는 통제권 탈취의 정황을 제공
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.734 · 1851.0ms
```
ValidationAgent: validation: alert=KPI-FP-C2-RSSI-WEATHER verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-C2-RSSI-WEATHER rule=unknown.yml
ReportAgent: report: alert=KPI-FP-C2-RSSI-WEATHER severity=l verdict=false_positive
(investigation 요약) C2 링크 재밍 후 비정상 세션 수립과 명령 시퀀스 번호의 불연속성이 관찰되어 C2 통제권 탈취가 의심된다. 미발신된 명령이 UAV에 의해 처리되는 것을 확인했으며, 이는 단순한 신호 간섭이나 링크 장애보다 명령 위조를 시사한다. 따라서 즉각적인 운용
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 l · conf None · 0.1ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-C2-RSSI-WEATHER rule=unknown.yml
ReportAgent: report: alert=KPI-FP-C2-RSSI-WEATHER severity=l verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.734 · 262.2ms
```
ValidationAgent: validation: alert=KPI-FP-C2-RSSI-WEATHER verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-C2-RSSI-WEATHER rule=unknown.yml
ReportAgent: report: alert=KPI-FP-C2-RSSI-WEATHER severity=l verdict=false_positive
(investigation 요약) 기상에 의한 C2 RSSI 일시 저하 상관분석: 신뢰 사례 4건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.734 · 1659.6ms
```
ValidationAgent: validation: alert=KPI-FP-C2-RSSI-WEATHER verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-C2-RSSI-WEATHER rule=unknown.yml
ReportAgent: report: alert=KPI-FP-C2-RSSI-WEATHER severity=l verdict=false_positive
(investigation 요약) C2 링크 하이재킹 및 명령 주입 공격이 의심된다. 기체가 지상국(GCS)으로부터 미발신된 명령을 수신했으며, C2 RSSI 일시 저하와 재접속 과정에서 비정상 세션이 생성되었다. 이는 단순 링크 장애보다 통제권 탈취를 시사한다.
```

## 오탐 AUTH-RETASK — 인가 운용자 기체 재지정  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.759 · 1956.4ms
```
InvestigationAgent: investigation: alert=KPI-FP-AUTH-RETASK trusted=3 degraded=False ti=0 conf=0.76
ValidationAgent: validation: alert=KPI-FP-AUTH-RETASK verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-AUTH-RETASK rule=unknown.yml
ReportAgent: report: alert=KPI-FP-AUTH-RETASK severity=i verdict=false_positive
(investigation 요약) 의심 공격: GCS 침해 및 다수 기체에 대한 임무 재지정 의심

핵심 근거: 인가된 계정을 이용한 비정상 시간/위치에서의 로그인과 단시간 내 다수 기체의 동시 재지정, 그리고 이를 통한 내부망 횡적 연결 시도.
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.759 · 2101.8ms
```
ValidationAgent: validation: alert=KPI-FP-AUTH-RETASK verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-AUTH-RETASK rule=unknown.yml
ReportAgent: report: alert=KPI-FP-AUTH-RETASK severity=i verdict=false_positive
(investigation 요약) 의심 공격: GCS를 침해한 공격자가 유효 계정을 이용하여 비정상 시간과 위치에서 로그인 후, 단시간 내에 다수 기체의 임무를 재지정하고 내부망으로 횡적 확산을 시도하였다. 

핵심 근거: 인가된 운용자 계정의 비정상적인 로그인 및 다수 기체의 동시 
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 i · conf None · 0.2ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-AUTH-RETASK rule=unknown.yml
ReportAgent: report: alert=KPI-FP-AUTH-RETASK severity=i verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.759 · 244.4ms
```
ValidationAgent: validation: alert=KPI-FP-AUTH-RETASK verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-AUTH-RETASK rule=unknown.yml
ReportAgent: report: alert=KPI-FP-AUTH-RETASK severity=i verdict=false_positive
(investigation 요약) 인가 운용자 기체 재지정 상관분석: 신뢰 사례 3건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.759 · 1440.3ms
```
ValidationAgent: validation: alert=KPI-FP-AUTH-RETASK verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-AUTH-RETASK rule=unknown.yml
ReportAgent: report: alert=KPI-FP-AUTH-RETASK severity=i verdict=false_positive
(investigation 요약) 의심 공격: GCS 침해로 인한 다수 기체에 대한 임무 위조 재지정

핵심 근거: 비정상 시간/위치에서 로그인 후 단시간 내 다수 기체 동시에 재지정, 내부망으로 횡적 연결 감지.
```

## 오탐 SATCOM-MAINT — 예정된 SATCOM 점검 재접속  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.748 · 2691.6ms
```
InvestigationAgent: investigation: alert=KPI-FP-SATCOM-MAINT trusted=5 degraded=False ti=0 conf=0.75
ValidationAgent: validation: alert=KPI-FP-SATCOM-MAINT verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-SATCOM-MAINT rule=unknown.yml
ReportAgent: report: alert=KPI-FP-SATCOM-MAINT severity=i verdict=false_positive
(investigation 요약) 예정된 점검 내에서 발생한 SATCOM 단말 재접속 경보는 실제 공격의 징후일 가능성이 있다. 다수 SATCOM 단말들의 동시 접속 실패와 무결성 이상, 특정 지역 통신 장애 집중 등이 관찰되어 SATCOM 단말과 관리망 무력화를 시도한 공격으로 추정
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.748 · 2293.2ms
```
ValidationAgent: validation: alert=KPI-FP-SATCOM-MAINT verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-SATCOM-MAINT rule=unknown.yml
ReportAgent: report: alert=KPI-FP-SATCOM-MAINT severity=i verdict=false_positive
(investigation 요약) 예정된 점검 중 SATCOM 단말의 재접속이 감지되었으나, 이는 다수의 SATCOM 단말 접속 실패와 특정 지역 통신 장애 집중과 연관되어 공격으로 의심된다. 무결성 이상 및 관리 채널 오류 증가로 보안 위협 수준이 높게 평가되며, MITRE ATT&
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 i · conf None · 0.2ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-SATCOM-MAINT rule=unknown.yml
ReportAgent: report: alert=KPI-FP-SATCOM-MAINT severity=i verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.748 · 338.5ms
```
ValidationAgent: validation: alert=KPI-FP-SATCOM-MAINT verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-SATCOM-MAINT rule=unknown.yml
ReportAgent: report: alert=KPI-FP-SATCOM-MAINT severity=i verdict=false_positive
(investigation 요약) 예정된 SATCOM 점검 재접속 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 i · conf 0.748 · 2385.0ms
```
ValidationAgent: validation: alert=KPI-FP-SATCOM-MAINT verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-SATCOM-MAINT rule=unknown.yml
ReportAgent: report: alert=KPI-FP-SATCOM-MAINT severity=i verdict=false_positive
(investigation 요약) 예정된 점검 중인 SATCOM 단말의 재접속은 위성 통신 링크 무력화 공격(SATCOM-TAKEDOWN-010)이나 중간자(MITM) 공격(SATCOM-MITM-003)으로 의심된다. 무결성 이상과 다수의 단말 접속 실패가 관찰되며, 이는 단순 장비 
```

## 오탐 EKF-TAKEOFF-CONVERGE — 이륙 직후 EKF 수렴 트랜지언트  (오탐)

**[baseline]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.729 · 2708.7ms
```
InvestigationAgent: investigation: alert=KPI-FP-EKF-TAKEOFF-CONVERGE trusted=5 degraded=False ti=0 conf=0.73
ValidationAgent: validation: alert=KPI-FP-EKF-TAKEOFF-CONVERGE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-EKF-TAKEOFF-CONVERGE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-EKF-TAKEOFF-CONVERGE severity=l verdict=false_positive
(investigation 요약) 이륙 직후 EKF 잔차 일시 상승은 C2 링크 하이재킹 및 명령 주입 공격의 결과로 기체가 비정상적인 명령을 수신했음을 시사한다. 미발신 명령 수신과 시퀀스 번호 불연속성을 통해 세션 하이재킹 정황을 확인할 수 있다. 이로 인해 운용자 의도와 다른 동
```

**[parallel]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.729 · 1788.7ms
```
ValidationAgent: validation: alert=KPI-FP-EKF-TAKEOFF-CONVERGE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-EKF-TAKEOFF-CONVERGE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-EKF-TAKEOFF-CONVERGE severity=l verdict=false_positive
(investigation 요약) 이륙 직후 EKF 잔차 일시 상승은 C2 링크 하이재킹과 위조 명령 주입을 의심케 한다. 기체가 지상국(GCS)으로부터 발신되지 않은 명령을 수신하고, 시퀀스 번호가 불연속적으로 나타났다. 이러한 현상은 통제권 탈취 공격의 핵심 증거이다.
```

**[router]** trace: `triage → rule_update → report` · 판정 false_positive · 심각도 l · conf None · 0.2ms
```
RuleUpdateAgent: rule_update: alert=KPI-FP-EKF-TAKEOFF-CONVERGE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-EKF-TAKEOFF-CONVERGE severity=l verdict=false_positive
(investigation 요약) (investigation 없음)
```

**[supervisor]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.729 · 350.1ms
```
ValidationAgent: validation: alert=KPI-FP-EKF-TAKEOFF-CONVERGE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-EKF-TAKEOFF-CONVERGE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-EKF-TAKEOFF-CONVERGE severity=l verdict=false_positive
(investigation 요약) 이륙 직후 EKF 수렴 트랜지언트 상관분석: 신뢰 사례 5건 (LLM 요약 생략 — 근거 충분)
```

**[wizblue]** trace: `triage → investigation → validation → rule_update → report` · 판정 false_positive · 심각도 l · conf 0.729 · 1942.5ms
```
ValidationAgent: validation: alert=KPI-FP-EKF-TAKEOFF-CONVERGE verdict=false_positive
RuleUpdateAgent: rule_update: alert=KPI-FP-EKF-TAKEOFF-CONVERGE rule=unknown.yml
ReportAgent: report: alert=KPI-FP-EKF-TAKEOFF-CONVERGE severity=l verdict=false_positive
(investigation 요약) 이륙 직후 EKF 잔차 일시 상승은 C2 링크 하이재킹 및 명령 주입 공격의 정황을 암시하며, 기체가 운용자 의도와 다른 동작을 보임. 특히 재밍 후 비정상 세션이 수립되는 것을 확인했고, 미발신 명령 수신과 시퀀스 번호 불연속성이 관찰되어 통제권 탈
```
