import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

# [1] 파일 경로 설정
DATA_PATH = r'C:\Users\ez\Downloads\UNSW_NB15_30Percent_Augmented.csv'
MODEL_SAVE_PATH = r'C:\Users\ez\FirstPenguin\xgboost_model.pkl'
ENCODER_SAVE_PATH = r'C:\Users\ez\FirstPenguin\feature_encoders.pkl'

def train_xgboost():
    print("📂 데이터 로드 중...")
    if not os.path.exists(DATA_PATH):
        print(f"❌ 파일을 찾을 수 없습니다: {DATA_PATH}"); return
    
    df = pd.read_csv(DATA_PATH, low_memory=False)

    # [2] 정답 유출 방지를 위한 컬럼 제거
    # 학습에 필요 없는 IP, 시간, 이미 정답이 포함된 점수 등을 제거합니다.
    drop_cols = ['srcip', 'dstip', 'attack_cat', 'label', 'risk_score', 'stime', 'ltime']
    X = df.drop(columns=[col for col in drop_cols if col in df.columns])
    
    # 타겟(y) 분리
    if 'risk_level' not in df.columns:
        print("❌ 'risk_level' 컬럼이 데이터에 없습니다."); return
    y_raw = df['risk_level']
    X = X.drop(columns=['risk_level'])

    # [3] 에러 해결: 문자열(Object) 컬럼을 카테고리 타입으로 변환
    # XGBoost가 처리할 수 있도록 모든 object 타입을 'category'로 바꿉니다.
    print("🛠️ 데이터 타입 변환 중 (Object -> Category)...")
    cat_features = X.select_dtypes(include=['object']).columns.tolist()
    for col in cat_features:
        X[col] = X[col].astype('category')

    # [4] 에러 해결: 타겟 라벨(y)을 0부터 시작하게 변환
    # [1,2,3,4,5] -> [0,1,2,3,4]
    print("🎯 타겟 라벨 인코딩 중...")
    le_y = LabelEncoder()
    y = le_y.fit_transform(y_raw)
    num_classes = len(np.unique(y))

    # [5] 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # [6] XGBoost 모델 설정 및 학습
    # enable_categorical=True 설정이 핵심입니다!
    print(f"🤖 XGBoost 학습 시작... (클래스 수: {num_classes})")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective='multi:softprob',
        num_class=num_classes,
        tree_method='hist',           # 카테고리 데이터 처리에 최적화
        enable_categorical=True,      # 글자 데이터를 자동으로 처리하게 함
        random_state=42,
        eval_metric='mlogloss'
    )

    model.fit(X_train, y_train)

    # [7] 성능 평가
    y_pred = model.predict(X_test)
    print("\n" + "="*50)
    print(f"✅ 모델 정확도: {accuracy_score(y_test, y_pred):.4f}")
    print("-" * 50)
    # 실제 risk_level 값으로 보고서를 뽑기 위해 target_names 설정
    target_names = [str(cls) for cls in le_y.classes_]
    print(classification_report(y_test, y_pred, target_names=target_names))
    print("="*50)

    # [8] 모델 및 인코더 저장
    print("💾 모델 저장 중...")
    with open(MODEL_SAVE_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    # 타겟 인코더도 함께 저장 (나중에 0~4를 다시 1~5로 바꾸기 위해)
    with open(ENCODER_SAVE_PATH, 'wb') as f:
        pickle.dump(le_y, f)

    print(f"✨ 학습 완료! 모델 저장 위치: {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    train_xgboost()