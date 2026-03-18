import pandas as pd
import matplotlib.pyplot as plt
import os

# ==========================================
# 1. 환경 설정 및 경로 정의
# ==========================================
# 입력 파일 경로 (사용자께서 명시하신 경로 기준)
input_path = r'C:\Users\ez\Downloads\com.csv' 
# 결과 저장 경로
output_path = r'C:\Users\ez\Downloads\UNSW_NB15_Risk_Labeled.csv'


# ==========================================
# 5. 통계 출력 및 원형 그래프 시각화
# ==========================================
risk_counts = df['risk_level'].value_counts().sort_index()
risk_labels = ['Level 0 (Normal)', 'Level 1 (Recon)', 'Level 2 (Analysis)', 
               'Level 3 (Exploit)', 'Level 4 (Critical)', 'Level 5 (LM/Worm)']

# 텍스트 결과 출력
print("\n" + "="*30)
print("📊 위험도별 데이터 분포 요약")
print("="*30)
for i, count in enumerate(risk_counts):
    print(f"{risk_labels[i]:<20} : {count:>8,d} 건")
print("="*30)

# 시각화 (원형 그래프)
plt.figure(figsize=(12, 8))
colors = ['#2ecc71', '#3498db', '#f1c40f', '#e67e22', '#e74c3c', '#8e44ad']
# Level 4, 5를 시각적으로 분리하여 강조
explode = [0, 0, 0, 0, 0.1, 0.2] 

plt.pie(risk_counts, 
        labels=[f"{risk_labels[i]}\n({risk_counts[i]:,})" for i in range(len(risk_counts))], 
        autopct='%1.1f%%', 
        startangle=140, 
        colors=colors, 
        explode=explode, 
        shadow=True)

plt.title('Lateral Movement Detection: 5-Step Risk Distribution', fontsize=16, fontweight='bold')
plt.tight_layout()
plt.show()