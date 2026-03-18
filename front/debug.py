import pickle
import pandas as pd
import numpy as np

with open('front/xgboost_model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('front/feature_encoders.pkl', 'rb') as f:
    le_y = pickle.load(f)

booster  = model.get_booster()
features = booster.feature_names
ftypes   = booster.feature_types

# 카테고리 피처는 문자열로, 나머지는 숫자로
X = pd.DataFrame([{f: '0' if t == 'c' else 0
                   for f, t in zip(features, ftypes or ['q']*len(features))}])

for col, f_type in zip(features, ftypes or []):
    if f_type == 'c':
        X[col] = X[col].astype(str).astype('category')
    else:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype(float)

preds  = model.predict(X)
labels = le_y.inverse_transform(preds)
print('raw preds:', preds)
print('labels:', labels)
print('label type:', type(labels[0]))