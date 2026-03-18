.env 파일 생성후

    OPENAI_API_KEY = [KEY]

입력 후 저장

    python -m venv venv

    venv\Scripts\activate

    pip install -r front/requirements.txt

    streamlit run front/app.py       

순서로 실행

🛡️ 수평 이동(Lateral Movement) 탐지 및 위험도 산정 시스템

SK Shieldus Rookies 프로젝트의 일환으로, UNSW-NB15 데이터셋을 활용하여 내부망 보안의 핵심인 '수평 이동' 공격을 실시간으로 탐지하고 대응하는 지능형 관제 시스템을 개발합니다.

📅 프로젝트 로드맵

Day 1: 기초 설계 및 검증 (완료)

[x] 브레인스토밍: 15개 후보 주제 중 6개 엄선 후 '수평 이동 탐지' 최종 선정

[x] 데이터 엔지니어링: UNSW-NB15 CSV(1~4) 병합 (약 105만 행) 및 49개 컬럼 분석

[x] 위험도 전략: 5단계 위험도 산정 로직(risk_label) 수립

[x] 1차 테스트: XGBoost 기반 모델 성능 테스트 (전체 정확도 99%, 고위험군 재현율 보완 필요 확인)

Day 2: 시스템 고도화 및 AI 에이전트 구축 (진행 중)

[ ] 인프라: GitHub 리포지토리 개설 및 CRUD 정책, 데이터 딕셔너리 명세화

[ ] 데이터: SMOTE 적용을 통한 데이터 불균형 해소 및 모델 성능 고도화

[ ] AI 에이전트: 3중 오케스트라 설계

Agent 1 (Risk Classifier): 실시간 유입 트래픽 위험도 판별

Agent 2 (Dashboard Gen): 정적/동적 데이터 기반 시각화 위젯 생성

Agent 3 (Orchestrator): 에이전트 간 워크플로우 제어 및 결과 통합

Day 3: 실시간 시뮬레이션 및 클라우드 배포

[ ] 시뮬레이션: Kali Linux를 활용한 실제 공격 수행 및 실시간 패킷 캡처

[ ] 실시간 관제: 5분 단위 자동 업데이트 대시보드 및 실시간 탐지 파이프라인 완성

[ ] 클라우드: AWS EC2/S3 기반 서버 구축 및 전체 시스템 배포

🤖 3중 오케스트라 AI 에이전트 아키텍처

위험 인지 에이전트 (Risk Agent)

모델 예측값과 네트워크 지표를 종합하여 현재 트래픽이 공격인지 아닌지 최종 확정합니다.

대시보드 생성 에이전트 (Dashboard Agent)

유입된 데이터를 분석하여 공격 분포, 주요 타겟 IP 등을 시각화 차트로 자동 변환합니다.

오케스트레이터 (Orchestrator)

두 에이전트의 충돌을 방지하고 사용자 요청에 맞는 최적의 분석 결과를 프런트엔드에 전달합니다.

🛠 기술 스택

Machine Learning: XGBoost, Scikit-learn, SMOTE

AI Agent: OpenAI, Tavily (Search)

Frontend: Streamlit (Real-time Dashboard)

Infra: AWS, Kali Linux, GitHub

Maintained by SK Shieldus Rookies Team🛡️ 수평 이동(Lateral Movement) 탐지 및 위험도 산정 시스템

SK Shieldus Rookies 프로젝트의 일환으로, UNSW-NB15 데이터셋을 활용하여 내부망 보안의 핵심인 '수평 이동' 공격을 실시간으로 탐지하고 대응하는 지능형 관제 시스템을 개발합니다.

📅 프로젝트 로드맵

Day 1: 기초 설계 및 검증 (완료)

[x] 브레인스토밍: 15개 후보 주제 중 6개 엄선 후 '수평 이동 탐지' 최종 선정

[x] 데이터 엔지니어링: UNSW-NB15 CSV(1~4) 병합 (약 105만 행) 및 49개 컬럼 분석

[x] 위험도 전략: 5단계 위험도 산정 로직(risk_label) 수립

[x] 1차 테스트: XGBoost 기반 모델 성능 테스트 (전체 정확도 99%, 고위험군 재현율 보완 필요 확인)

Day 2: 시스템 고도화 및 AI 에이전트 구축 (진행 중)

[ ] 인프라: GitHub 리포지토리 개설 및 CRUD 정책, 데이터 딕셔너리 명세화

[ ] 데이터: SMOTE 적용을 통한 데이터 불균형 해소 및 모델 성능 고도화

[ ] AI 에이전트: 3중 오케스트라 설계

Agent 1 (Risk Classifier): 실시간 유입 트래픽 위험도 판별

Agent 2 (Dashboard Gen): 정적/동적 데이터 기반 시각화 위젯 생성

Agent 3 (Orchestrator): 에이전트 간 워크플로우 제어 및 결과 통합

Day 3: 실시간 시뮬레이션 및 클라우드 배포

[ ] 시뮬레이션: Kali Linux를 활용한 실제 공격 수행 및 실시간 패킷 캡처

[ ] 실시간 관제: 5분 단위 자동 업데이트 대시보드 및 실시간 탐지 파이프라인 완성

[ ] 클라우드: AWS EC2/S3 기반 서버 구축 및 전체 시스템 배포

🤖 3중 오케스트라 AI 에이전트 아키텍처

위험 인지 에이전트 (Risk Agent)

모델 예측값과 네트워크 지표를 종합하여 현재 트래픽이 공격인지 아닌지 최종 확정합니다.

대시보드 생성 에이전트 (Dashboard Agent)

유입된 데이터를 분석하여 공격 분포, 주요 타겟 IP 등을 시각화 차트로 자동 변환합니다.

오케스트레이터 (Orchestrator)

두 에이전트의 충돌을 방지하고 사용자 요청에 맞는 최적의 분석 결과를 프런트엔드에 전달합니다.

🛠 기술 스택

Machine Learning: XGBoost, Scikit-learn, SMOTE

AI Agent: OpenAI, Tavily (Search)

Frontend: Streamlit (Real-time Dashboard)

Infra: AWS, Kali Linux, GitHub

Maintained by SK Shieldus Rookies Team