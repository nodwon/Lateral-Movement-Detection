import numpy as np
import pandas as pd

def predict_risk(model, features_df: pd.DataFrame) -> float:
    """
    model.pkl로 Risk Score 예측
    - 반환값: 0.0 ~ 1.0 float
    """
    try:
        # predict_proba 지원 모델 (RandomForest, XGBoost 등)
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(features_df)
            # 클래스 1(위험) 확률 반환
            score = float(proba[0][1])
        else:
            # predict만 있는 모델 → 0 or 1 반환
            pred = model.predict(features_df)
            score = float(pred[0])

        # 0~1 범위 클리핑
        return float(np.clip(score, 0.0, 1.0))

    except Exception as e:
        # 피처 컬럼 불일치 등의 오류 → 룰 기반으로 fallback
        return _rule_based_score(features_df)


def _rule_based_score(features_df: pd.DataFrame) -> float:
    """
    model.pkl 실패 시 룰 기반 점수 계산 (fallback)
    """
    row = features_df.iloc[0]
    score = 0.0

    lateral_ratio = row.get('lateral_port_ratio', 0)
    avg_dest      = row.get('avg_dest_per_src', 0)
    events_ph     = row.get('events_per_hour', 0)

    # 측면이동 포트 비율이 높을수록 위험
    score += lateral_ratio * 0.5

    # 한 소스가 많은 목적지 접근 (스캐닝)
    if avg_dest > 10:
        score += 0.3
    elif avg_dest > 5:
        score += 0.15

    # 시간당 이벤트 폭발
    if events_ph > 1000:
        score += 0.2
    elif events_ph > 500:
        score += 0.1

    return float(np.clip(score, 0.0, 1.0))
