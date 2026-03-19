import pandas as pd
import numpy as np
import xgboost as xgb
import pickle
import os

# [1] 모델 및 인코더 경로 
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
            print("✅ AI Agent: 4단계 실무형 모델 로드 완료!")
        except Exception as e:
            print(f"⚠️ AI Agent 에러: {e}")

    def _preprocess_data(self, df):
        X = df.copy()
        # 불필요한 컬럼 제거
        drop_cols = ['label', 'attack_cat', 'risk_level', 'risk_score', 'stime', 'ltime', 'id', 'sport', 'dsport']
        X = X.drop(columns=[col for col in drop_cols if col in X.columns], errors='ignore')

        # 파생 변수 생성
        if 'sbytes' in X.columns and 'spkts' in X.columns:
            X['avg_sbytes_per_pkt'] = X['sbytes'] / (X['spkts'] + 1)
        if 'dbytes' in X.columns and 'dpkts' in X.columns:
            X['avg_dbytes_per_pkt'] = X['dbytes'] / (X['dpkts'] + 1)
        if 'sbytes' in X.columns and 'dbytes' in X.columns:
            X['byte_asymmetry'] = (X['sbytes'] - X['dbytes']) / (X['sbytes'] + X['dbytes'] + 1)
        if 'ct_srv_src' in X.columns and 'dur' in X.columns:
            X['conn_rate_per_sec'] = X['ct_srv_src'] / (X['dur'] + 0.0001)
        if 'dur' in X.columns and 'sbytes' in X.columns:
            X['bytes_per_dur'] = X['sbytes'] / (X['dur'] + 0.0001)
        if 'dur' in X.columns and 'spkts' in X.columns:
            X['pkts_per_dur'] = X['spkts'] / (X['dur'] + 0.0001)
        if 'sbytes' in X.columns and 'sloss' in X.columns:
            X['loss_to_bytes_ratio'] = X['sloss'] / (X['sbytes'] + 1)

        # 단어장(Encoder) 적용
        if self.encoder_dict:
            for col, le in self.encoder_dict.items():
                if col in X.columns:
                    known_classes = set(le.classes_)
                    X[col] = X[col].astype(str).apply(lambda x: x if x in known_classes else le.classes_[0])
                    X[col] = le.transform(X[col])

        # 피처 순서 맞추기
        if self.model and hasattr(self.model, 'feature_names_in_'):
            expected = list(self.model.feature_names_in_)
            for col in expected:
                if col not in X.columns: X[col] = 0
            X = X[expected]
        return X

    def analyze(self, df):
<<<<<<< HEAD
        if self.model is None:
            return {"risk_score": 0.0, "lm_suspected": False, "summary_text": "AI 모델 미로드"}
=======
        # 1. 내부 컬럼명 → 모델 피처명으로 매핑
        # 모델 피처: sport, dsport, proto, sbytes, service 등 원본 UNSW-NB15 컬럼명
        # is_internal, is_critical_port 는 이미 동일한 이름이므로 rename 불필요
        # 모델 피처 매핑 (sport/dsport 제거됨, 파생 피처 추가됨)
        rename_map = {
            "ProtoRaw":    "proto",
            "Bytes":       "sbytes",
            "Application": "service",
        }
        X = df.rename(columns=rename_map).copy()
>>>>>>> f36dcd2474ef6edd46c938e2648e1c0e17fb7f8c

        try:
            X_processed = self._preprocess_data(df)
            proba = self.model.predict_proba(X_processed)
            
            # [핵심 변경] 평균이 아니라 '최댓값'을 기준으로 위협을 판단합니다 (스나이퍼 모드)
            max_p_low = np.max(proba[:, 1])
            max_p_med = np.max(proba[:, 2])
            max_p_crit = np.max(proba[:, 3])
            
            # 가장 높은 확률을 가진 클래스의 점수를 부여
            if max_p_crit > 0.1: # 10% 확률이라도 Critical이 발견되면!
                risk_score = 5.0
                status = "🚨 [Critical] 치명적 위협(측면 이동)이 감지되었습니다!"
                is_lm = True
            elif max_p_med > 0.3:
                risk_score = 3.5
                status = "⚠️ [Medium] 침투 시도 및 고위험 트래픽이 감지되었습니다."
                is_lm = False
            elif max_p_low > 0.3:
                risk_score = 1.5
                status = "👀 [Low] 주의가 필요한 정찰/스캔 활동이 감지되었습니다."
                is_lm = False
            else:
<<<<<<< HEAD
                risk_score = 0.0
                status = "✅ 특이 사항 없는 안전한 상태입니다."
                is_lm = False
=======
                labels = preds

            df = df.copy()
            df["predicted_label"] = labels

            # 숫자형이면 threshold 기반, 문자열이면 공격 키워드 기반 판단
            sample = labels[0]
            if isinstance(sample, (int, float, np.integer, np.floating)):
                # 숫자: risk_score 기준 (4 이상 = 고위험)
                df["predicted_risk_num"] = pd.to_numeric(df["predicted_label"], errors="coerce").fillna(0)
                high_risk_df = df[df["predicted_risk_num"] >= 2]  # 클래스 [1,2,3] 기준 2 이상 = 위험
                avg_risk = round(float(df["predicted_risk_num"].mean()), 2)
            else:
                # 문자열: Normal이 아닌 것 = 공격
                ATTACK_KEYWORDS = {"lateral", "exploit", "backdoor", "shellcode",
                                   "reconnaissance", "fuzzers", "worms", "dos",
                                   "analysis", "generic"}
                def is_attack(label):
                    if str(label).strip().lower() == "normal": return False
                    if str(label).strip() in ("0", ""): return False
                    return True
                high_risk_df = df[df["predicted_label"].apply(is_attack)]
                avg_risk = round(len(high_risk_df) / max(len(df), 1), 2)

            suspicious_host = (
                high_risk_df["SourceAddress"].mode()[0]
                if not high_risk_df.empty and "SourceAddress" in high_risk_df.columns
                else "N/A"
            )
>>>>>>> f36dcd2474ef6edd46c938e2648e1c0e17fb7f8c

            return {
                "risk_score": risk_score,
                "lm_suspected": is_lm,
                "summary_text": f"AI 분석 결과: {status} (위험 점수: {risk_score})"
            }
        except Exception as e:
            return {"risk_score": 0.0, "lm_suspected": False, "summary_text": f"❌ 분석 에러: {e}"}