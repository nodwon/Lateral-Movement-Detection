import pandas as pd
import numpy as np
import xgboost as xgb
import pickle
import os
import traceback

# [1] 모델 경로 (다원님 폴더 구조에 맞춰 고정)
MODEL_PATH = r'C:\Users\ez\FirstPenguin\front\xgboost_model.pkl'
ENCODER_PATH = r'C:\Users\ez\FirstPenguin\front\feature_encoders.pkl'

class SecurityAIAgent:
    def __init__(self):
        self.model = None
        self.encoder_dict = None
        self._load_model()

    def _load_model(self):
        try:
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
            with open(ENCODER_PATH, 'rb') as f:
                self.encoder_dict = pickle.load(f)
            print("✅ AI Agent: 4단계 실무형 모델 로드 성공!")
        except Exception as e:
            print(f"⚠️ AI Agent 로드 에러: {e}")

    def _preprocess_data(self, df):
        X = df.copy()

        # [핵심 1] 대시보드 이름을 AI 이름으로 강제 번역
        column_mapping = {
            "SourceAddress": "srcip",
            "DestAddress": "dstip",
            "DestPort": "dsport",
            "Bytes": "sbytes",
            "Protocol": "proto",
            "Application": "service"
        }
        X = X.rename(columns=column_mapping)

        # [핵심 2] 부족한 피처를 기본값으로 채우기 (AI가 0점 처리하는 것 방지)
        # 대시보드 데이터에 없는 정보들을 최소한의 공격 징후로 채워줍니다.
        if 'spkts' not in X.columns: X['spkts'] = 2  # 최소 2패킷 이상으로 가정
        if 'dpkts' not in X.columns: X['dpkts'] = 1
        if 'dur' not in X.columns: X['dur'] = 0.5    # 0.5초 정도 지속된 것으로 가정

        # [핵심 3] 프로토콜 소문자 통일 (TCP -> tcp)
        if 'proto' in X.columns:
            X['proto'] = X['proto'].astype(str).str.lower()
        if 'service' in X.columns:
            X['service'] = X['service'].astype(str).str.lower()

        # A. 노이즈 컬럼 제거
        drop_cols = ['label', 'attack_cat', 'risk_level', 'risk_score', 'stime', 'ltime', 'id', 'sport']
        X = X.drop(columns=[col for col in drop_cols if col in X.columns], errors='ignore')

        # B. 파생 변수 생성 (AI가 공격을 판단하는 결정적 힌트들)
        X['avg_sbytes_per_pkt'] = X['sbytes'] / (X['spkts'] + 1)
        X['byte_asymmetry'] = (X['sbytes'] - 500) / (X['sbytes'] + 501) # dbytes 부재 시 보정
        X['pkts_per_dur'] = X['spkts'] / (X['dur'] + 0.0001)

        # C. 저장된 단어장으로 번역 (LabelEncoding)
        if self.encoder_dict:
            for col, le in self.encoder_dict.items():
                if col in X.columns:
                    known_classes = set(le.classes_)
                    # 모르는 글자는 단어장의 첫 번째 단어로 대체
                    X[col] = X[col].astype(str).map(lambda x: x if x in known_classes else le.classes_[0])
                    X[col] = le.transform(X[col])

        # D. 모델이 공부한 순서대로 컬럼 정렬
        if self.model and hasattr(self.model, 'feature_names_in_'):
            expected = list(self.model.feature_names_in_)
            for col in expected:
                if col not in X.columns: X[col] = 0
            X = X[expected]
            
        return X

    def analyze(self, df):
        if self.model is None:
            return {"risk_score": 0.0, "lm_suspected": False, "summary_text": "AI 모델 미연결"}

        try:
            X_processed = self._preprocess_data(df)
            proba = self.model.predict_proba(X_processed)
            num_classes = proba.shape[1] # 모델이 가진 클래스 개수 확인 (3개 또는 4개)

            # [핵심 4] 스나이퍼 탐지 로직 (평균이 아닌 최댓값 기준)
            # 모델이 4개 클래스면 index 3을 보고, 3개 클래스면 index 2를 최고 위험으로 봅니다.
            crit_idx = num_classes - 1 
            max_crit_prob = np.max(proba[:, crit_idx])
            
            # 위험 점수 및 상태 텍스트 결정
            if max_crit_prob > 0.3: # 30%만 넘어도 즉시 경보
                risk_score = 5.0
                status = "🚨 [Critical] 측면 이동(Lateral Movement) 공격이 확실시됩니다!"
                is_lm = True
            elif num_classes > 2 and np.max(proba[:, crit_idx-1]) > 0.4:
                risk_score = 3.5
                status = "⚠️ [Medium] 침투 시도 또는 스캔 활동이 감지되었습니다."
                is_lm = False
            else:
                risk_score = 0.0
                status = "✅ 정상적인 네트워크 트래픽입니다."
                is_lm = False

            return {
                "risk_score": risk_score,
                "lm_suspected": is_lm,
                "summary_text": f"AI 분석 결과: {status} (위험 점수: {risk_score})"
            }
        except Exception as e:
            return {"risk_score": 0.0, "lm_suspected": False, "summary_text": f"❌ 분석 에러: {e}"}