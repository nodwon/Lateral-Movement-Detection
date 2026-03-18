import pandas as pd
import numpy as np
import random

# 1. 기존 데이터 로드
file_path = r'C:\Users\ez\Downloads\UNSW_NB15_Risk_Labeled.csv'
print("📂 원본 데이터를 분석 중입니다...")
df = pd.read_csv(file_path, low_memory=False)

# ---------------------------------------------------------
# [Step 1] 30% 비중을 위한 필요 데이터 수 계산
# ---------------------------------------------------------
# 현재 정상(0) 데이터 수 기준, 전체의 30%가 공격이 되도록 계산
# 계산식: (기존 공격 + 추가 공격) / (전체 + 추가 공격) = 0.3
n_normal = len(df[df['label'] == 0])
n_current_attack = len(df[df['label'] == 1])
# 추가로 필요한 수 ≒ (0.3 * n_normal / 0.7) - n_current_attack
n_to_add = int((0.3 * n_normal / 0.7) - n_current_attack)

print(f"📊 현재 정상 데이터: {n_normal:,} 건")
print(f"🎯 목표: 공격 데이터 약 {n_to_add + n_current_attack:,} 건 (30% 대)")

# ---------------------------------------------------------
# [Step 2] 고도화된 수평 이동(LM) 합성 데이터 생성
# ---------------------------------------------------------
print(f"🚀 {n_to_add:,} 건의 수평 이동 데이터를 생성 중입니다... (잠시만 기다려주세요)")

# 정상 데이터에서 베이스 샘플 추출 (속도를 위해 대량 추출)
synthetic_base = df[df['label'] == 0].sample(n=n_to_add, replace=True, random_state=42).copy()

# 내부 IP 및 공격 전용 포트 설정
internal_ips = [f'149.171.1.{i}' for i in range(1, 255)]
lm_ports = [445, 3389, 22, 5985, 139, 135] # SMB, RDP, SSH, WinRM, RPC

# 수평 이동 특징 주입
synthetic_base['srcip'] = [random.choice(internal_ips) for _ in range(n_to_add)]
synthetic_base['dstip'] = [random.choice(internal_ips) for _ in range(n_to_add)]
synthetic_base['dsport'] = [random.choice(lm_ports) for _ in range(n_to_add)]
synthetic_base['label'] = 1
synthetic_base['attack_cat'] = 'Worms'
synthetic_base['risk_level'] = 5

# 공격 트래픽은 보통 지속 시간이 짧고 반복적이므로 dur와 bytes를 살짝 조정
synthetic_base['dur'] = synthetic_base['dur'].apply(lambda x: x * random.uniform(0.1, 0.5))
synthetic_base['sbytes'] = synthetic_base['sbytes'].apply(lambda x: x + random.randint(500, 2000))

# 데이터 병합
df_final = pd.concat([df, synthetic_base], ignore_index=True)

# ---------------------------------------------------------
# [Step 3] 새로운 분석용 컬럼 추가 (Feature Engineering) - 수정본
# ---------------------------------------------------------
print("🎨 대시보드 및 학습용 새로운 컬럼 추가 중...")

internal_prefix = '149.171.'

# 1. 내부망 이동 여부 (전부 df_final로 통일!)
df_final['is_internal'] = ((df_final['srcip'].str.startswith(internal_prefix, na=False)) & 
                           (df_final['dstip'].str.startswith(internal_prefix, na=False))).astype(int)

# 2. 크리티컬 포트 사용 여부
df_final['is_critical_port'] = df_final['dsport'].isin(lm_ports).astype(int)

# 3. 위험 점수
df_final['risk_score'] = df_final['risk_level'] * 20
# ---------------------------------------------------------
# [Step 4] 최종 파일 저장
# ---------------------------------------------------------
output_path = r'C:\Users\ez\Downloads\UNSW_NB15_30Percent_Augmented.csv'
df_final.to_csv(output_path, index=False)

print("-" * 50)
print(f"✅ 최종 데이터 생성 완료!")
print(f"📈 전체 행 수: {len(df_final):,} 행")
print(f"🔥 공격 데이터 수: {df_final['label'].sum():,} 건")
print(f"📊 최종 공격 비중: {(df_final['label'].sum() / len(df_final)) * 100:.2f}%")
print(f"💾 저장 경로: {output_path}")
print("-" * 50)