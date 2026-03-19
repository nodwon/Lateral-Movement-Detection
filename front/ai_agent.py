import pandas as pd
import pickle
import numpy as np
import os

class SecurityAIAgent:
    def __init__(self, model_path='xgboost_model.pkl', encoder_path='feature_encoders.pkl'):
        base_path = os.path.dirname(__file__)
        m_path = os.path.join(base_path, model_path)
        e_path = os.path.join(base_path, encoder_path)
        
        with open(m_path, 'rb') as f:
            self.model = pickle.load(f)
        with open(e_path, 'rb') as f:
            self.le_y = pickle.load(f)
        
        booster = self.model.get_booster()
        self.expected_features = booster.feature_names
        self.feature_types = booster.feature_types

    def analyze(self, df):
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

        # 중복 컬럼 제거
        if X.columns.duplicated().any():
            X = X.loc[:, ~X.columns.duplicated()]

        # 2. 모델이 요구하는 피처만 추출 (없는 컬럼은 0으로 채움)
        X = X.reindex(columns=self.expected_features, fill_value=0)

        # 3. 데이터 타입 완벽 일치
        if self.feature_types:
            for col, f_type in zip(self.expected_features, self.feature_types):
                if f_type == 'c':
                    # 카테고리형 — 문자열로 변환 후 category로 캐스팅
                    # (숫자 0으로 fill된 값도 문자열 "0"으로 처리)
                    X[col] = X[col].astype(str).astype('category')
                else:
                    X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype(float)

        # 4. AI 예측 수행
        try:
            preds = self.model.predict(X[self.expected_features])

            # le_y가 있으면 역변환, 없으면 raw 예측값 사용
            if self.le_y is not None:
                labels = self.le_y.inverse_transform(preds)
            else:
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

            return {
                "lm_suspected":    len(high_risk_df) > 0,
                "risk_score":      avg_risk,
                "high_risk_count": len(high_risk_df),
                "suspicious_host": suspicious_host,
                "summary_text": (
                    f"AI(XGBoost) 분석 완료\n"
                    f"- 위협 탐지: {len(high_risk_df):,}건 / 전체 {len(df):,}건\n"
                    f"- 평균 위험도: {avg_risk}\n"
                    f"- 주요 의심 호스트: {suspicious_host}"
                )
            }
        except Exception as e:
            return {
                "lm_suspected": False,
                "risk_score":   0.0,
                "summary_text": f"⚠️ AI 판별 에러: {str(e)}"
            }