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
        # 1. 컬럼명 매핑
        rename_map = {
            "SourceAddress": "srcip",
            "DestAddress": "dstip",
            "DestPort": "dsport",
            "SrcPort": "sport",
            "Bytes": "sbytes",
            "ProtoRaw": "proto",
            "Application": "service"
        }
        X = df.rename(columns=rename_map).copy()

        # ---------------- [ 🔥 이 부분이 핵심 해결 포인트 ] ----------------
        # 이름이 같은 컬럼이 있으면 reindex가 불가능하므로 중복을 제거합니다.
        if X.columns.duplicated().any():
            X = X.loc[:, ~X.columns.duplicated()]
        # ----------------------------------------------------------------

        # 2. 데이터 규격 강제 일치 (순서 정렬 및 누락 컬럼 보충)
        # 이제 중복이 없으므로 reindex가 정상 작동합니다.
        X = X.reindex(columns=self.expected_features, fill_value=0)

        # 3. 데이터 타입 완벽 일치
        if self.feature_types:
            for col, f_type in zip(self.expected_features, self.feature_types):
                if f_type == 'c':
                    X[col] = X[col].astype('category')
                else:
                    X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype(float)

        # 4. AI 예측 수행
        try:
            preds = self.model.predict(X[self.expected_features])
            df['predicted_risk'] = self.le_y.inverse_transform(preds)
            
            high_risk_df = df[df['predicted_risk'] >= 4]
            avg_risk = round(df['predicted_risk'].mean(), 2)
            
            return {
                "lm_suspected": len(high_risk_df) > 0,
                "risk_score": avg_risk,
                "suspicious_host": high_risk_df['SourceAddress'].mode()[0] if not high_risk_df.empty else "N/A",
                "summary_text": f"AI 분석 완료: 위협 탐지 {len(high_risk_df)}건 (평균 위험도: {avg_risk})"
            }
        except Exception as e:
            return {
                "lm_suspected": False,
                "risk_score": 0.0,
                "summary_text": f"⚠️ AI 판별 에러: {str(e)}"
            }