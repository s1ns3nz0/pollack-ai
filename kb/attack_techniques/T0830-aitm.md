# MITRE ATT&CK for ICS — T0830 Adversary-in-the-Middle

OT 통신 경로에 끼어들어 명령/원격측정을 가로채거나 변조. UAV 맥락에서는 C2/데이터링크
중간자(비인가 GCS 접속, 명령 시퀀스 이상)로 발현. 관련 탐지: S2 C2 하이재킹
(C2_Whitelisted_GCS_List 화이트리스트 이탈), 명령 폭증 임계.
