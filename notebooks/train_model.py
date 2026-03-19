import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, f1_score
from imblearn.over_sampling import SMOTE
import pickle
import os

# [1] 파일 경로 설정 (4단계 전용 파일명 지정)
DATA_PATH = r'C:\Users\ez\FirstPenguin\UNSW_NB15_4Level_Augmented.csv'
MODEL_SAVE_PATH = r'C:\Users\ez\FirstPenguin\xgboost_model.pkl'
ENCODER_SAVE_PATH = r'C:\Users\ez\FirstPenguin\feature_encoders.pkl'

def train_xgboost_4_level():
    print("📂 4단계 실무형 데이터 로드 중...")
    if not os.path.exists(DATA_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {DATA_PATH}"); return
    
    df = pd.read_csv(DATA_PATH, low_memory=False)

    print("🛠️ 강력한 피처 엔지니어링 적용 중...")
    drop_cols = ['srcip', 'dstip', 'attack_cat', 'label', 'risk_score', 'stime', 'ltime', 'id', 'sport', 'dsport']
    X = df.drop(columns=[col for col in drop_cols if col in df.columns])
    
    y_raw = df['risk_level']
    X = X.drop(columns=['risk_level'], errors='ignore')

    # [마법의 가루 파생 변수 유지]
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

    print("🛠️ 데이터 인코딩 중...")
    le_features = {}
    cat_features = X.select_dtypes(include=['object']).columns.tolist()
    for col in cat_features:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        le_features[col] = le

    le_y = LabelEncoder()
    y = le_y.fit_transform(y_raw)
    num_classes = len(np.unique(y))
    class_labels = le_y.classes_

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"⚖️ SMOTE 밸런스 조정 중 (학습 데이터: {len(X_train)}건)...")
    smote = SMOTE(random_state=42, k_neighbors=3) 
    X_res, y_res = smote.fit_resample(X_train, y_train)
    
    # 4단계 체제에 맞춘 정밀 가중치 설정
    print("🔥 4단계 클래스 가중치 최적화 중...")
    weights_dict = {
        0: 0.2,    # Level 0 (Normal): 너무 많으므로 비중 대폭 축소
        1: 3.0,    # Level 1 (Low): 특징이 약하므로 높은 가중치 부여
        2: 1.0,    # Level 2 (Medium): 원본 데이터에 이미 충분히 많음
        3: 5.0     # Level 3 (Critical): 탐지 실패 시 치명적이므로 최고 가중치 부여
    }
    
    sample_weights = np.array([
        weights_dict.get(class_labels[val], 1.0) for val in y_res
    ])

    print(f"🤖 실무형 4단계 XGBoost 학습 시작...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=7,              
        min_child_weight=2,       
        learning_rate=0.05,
        objective='multi:softprob',
        num_class=num_classes,
        tree_method='hist',
        random_state=42,
        eval_metric='mlogloss'
    )

    model.fit(
        X_res, y_res, 
        sample_weight=sample_weights
    )

    # [8] 성능 평가 (동적 네이밍 처리로 에러 완벽 차단)
    y_pred_probs = model.predict_proba(X_test)
    y_pred = np.argmax(y_pred_probs, axis=1)
    
    print("\n" + "="*50)
    print(f"✅ 모델 정확도: {accuracy_score(y_test, y_pred):.4f}")
    print(f"🎯 Macro F1-Score: {f1_score(y_test, y_pred, average='macro'):.4f}")
    print("-" * 50)
    
    actual_classes = np.unique(y_test)
    all_target_names = {
        0: 'Level 0 (Normal)', 
        1: 'Level 1 (Low)', 
        2: 'Level 2 (Medium)', 
        3: 'Level 3 (Critical)'
    }
    target_names = [all_target_names[val] for val in actual_classes]
    
    print(classification_report(y_test, y_pred, target_names=target_names))
    print("="*50)

    print("💾 4단계 전용 모델 저장 중...")
    with open(MODEL_SAVE_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(ENCODER_SAVE_PATH, 'wb') as f:
        pickle.dump(le_features, f) # ✅ Feature 단어장을 저장하도록 변경!
        

    print(f"✨ 4단계 모델 학습 완료! 위치: {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    train_xgboost_4_level()