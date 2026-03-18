from matplotlib import pyplot as plt
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder  # 추가됨
import numpy as np
# 1. 데이터 로드
file_path = r'C:\Users\ez\Downloads\UNSW_NB15_Risk_Labeled.csv'
print("📂 데이터를 불러오는 중입니다...")
df = pd.read_csv(file_path, low_memory=False)

# 2. 전처리
# 학습에 불필요한 컬럼 제거
drop_cols = ['srcip', 'sport', 'dstip', 'dsport', 'stime', 'ltime', 'attack_cat', 'label', 'risk_level']
X = df.drop(columns=drop_cols)
y = df['risk_level']

# [핵심 수정] LabelEncoder를 사용하여 라벨을 0부터 시작하도록 변환
le = LabelEncoder()
y = le.fit_transform(y)
print(f"✅ 라벨 변환 완료: {le.classes_} -> {range(len(le.classes_))}")

# 범주형 변수 처리
X = pd.get_dummies(X)

# 3. 데이터 분할
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. 모델 학습
print("🚀 XGBoost 학습 시작...")
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    objective='multi:softprob',
    tree_method='hist',
    random_state=42
)

model.fit(X_train, y_train)

# 5. 결과 확인
print("\n✅ 학습 완료! 성능 보고서:")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=[str(c) for c in le.classes_]))

# ==========================================================
# 여기에 아래 코드를 추가하세요! (피처 중요도 분석)
# ==========================================================
import numpy as np

print("\n🔍 모델의 판단 근거(Feature Importance) 분석 중...")

# 1. 피처 중요도 추출
importances = model.feature_importances_
feature_names = X.columns
indices = np.argsort(importances)[-10:]  # 상위 10개 피처 선정

# 2. 시각화 (막대 그래프)
plt.figure(figsize=(10, 6))
plt.title("Lateral Movement Detection - Top 10 Features", fontsize=15)
plt.barh(range(len(indices)), importances[indices], color='skyblue', align='center')
plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
plt.xlabel('Relative Importance')
plt.tight_layout()

# 그래프 출력
plt.show()

# 3. 중요도 수치 출력
print("\n📊 상위 10개 피처 중요도 상세:")
for i in reversed(indices):
    print(f"{feature_names[i]}: {importances[i]:.4f}")