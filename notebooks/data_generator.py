import pandas as pd
import numpy as np
import random
import os

# [파일 경로 설정] - 본인 환경에 맞게 경로 확인!
BASE_DATA_PATH = r'C:\Users\ez\Downloads\UNSW_NB15_Risk_Labeled.csv' 
SAVE_DATA_PATH = r'C:\Users\ez\FirstPenguin\UNSW_NB15_4Level_Augmented.csv'

CRITICAL_PORTS = [445, 3389, 22, 5985, 135, 5900, 1433, 80, 21, 23, 8080]

def generate_4level_data():
    print("🏢 [데이터 생성기] 실무형 4단계(Normal/Low/Medium/Critical) 맞춤형 데이터 생성 시작...")
    
    if not os.path.exists(BASE_DATA_PATH):
        print(f"❌ 에러: 원본 파일({BASE_DATA_PATH})이 없습니다."); return

    df_base = pd.read_csv(BASE_DATA_PATH, low_memory=False)
    
    # 1. 기존 5단계 데이터를 4단계로 매핑
    print("🔄 기존 데이터를 4단계 실무형 등급으로 재분류 중...")
    if 'risk_level' not in df_base.columns:
        df_base['risk_level'] = 0
        
    def compress_risk_4_level(x):
        if x == 0: return 0               # Level 0 (Normal): 정상
        elif x == 1: return 1             # Level 1 (Low): 정찰/스캔
        elif x in [2, 3]: return 2        # Level 2 (Medium): 취약점 분석/익스플로잇
        elif x in [4, 5]: return 3        # Level 3 (Critical): 백도어/DoS/측면이동
        else: return 0

    df_base['risk_level'] = df_base['risk_level'].apply(compress_risk_4_level)

    internal_ips = [f'149.171.1.{i}' for i in range(1, 255)]
    new_rows = []
    current_time = 1421927400 
    target_count = 100000 
    
    # 2. [Level 1: Low] 정찰 및 스캔 데이터 강제 주입 (전체의 30%)
    print("🔍 [Level 1] 스캔/정찰(Low) 데이터 주입 중...")
    while len(new_rows) < (target_count * 0.3):
        src = random.choice(internal_ips); dst = random.choice(internal_ips)
        scan_time = current_time + random.randint(0, 100000)
        new_rows.append({
            'srcip': src, 'dstip': dst, 'dsport': random.choice([22, 80, 443, 3389]), 
            'dur': random.uniform(0.001, 0.1), 'sbytes': random.randint(100, 500), 'dbytes': random.randint(0, 200),
            'stime': scan_time, 'ltime': scan_time + 1,
            'proto': 'tcp', 'state': 'FIN', 'label': 1,
            'attack_cat': 'Reconnaissance',
            'risk_level': 1,  # Level 1 지정
            'risk_score': random.randint(30, 50)
        })

    # 3. [Level 3: Critical] 측면 이동 및 웜 확산 연쇄 경로 주입 (전체의 50%)
    print("🔗 [Level 3] 5-Hop 측면이동(Critical) 경로 주입 중...")
    while len(new_rows) < (target_count * 0.8):
        chain_len = random.randint(5, 10) 
        path = random.sample(internal_ips, chain_len + 1)
        chain_time = current_time + random.randint(0, 100000)
        
        for i in range(len(path) - 1):
            src = path[i]; dst = path[i+1]
            chain_time += random.randint(120, 600) 
            new_rows.append({
                'srcip': src, 'dstip': dst, 'dsport': random.choice(CRITICAL_PORTS),
                'dur': random.uniform(0.1, 3.0), 'sbytes': random.randint(2000, 50000), 'dbytes': random.randint(1000, 25000),
                'stime': chain_time, 'ltime': chain_time + 1,
                'proto': 'tcp', 'state': 'CON', 'label': 1,
                'attack_cat': 'Worms', 
                'risk_level': 3,  # Level 3 지정
                'risk_score': random.randint(85, 100)
            })

    # 4. [Level 3: Critical] 단발성 고위험 데이터 주입 (전체의 20%)
    print("🎯 [Level 3] 단발성 고위험 공격 추가 중...")
    while len(new_rows) < target_count:
        src, dst = random.sample(internal_ips, 2)
        attack_time = current_time + random.randint(0, 200000)
        new_rows.append({
            'srcip': src, 'dstip': dst, 'dsport': random.choice(CRITICAL_PORTS),
            'dur': random.uniform(0.1, 2.0), 'sbytes': random.randint(1000, 20000), 'dbytes': random.randint(500, 10000),
            'stime': attack_time, 'ltime': attack_time + 1,
            'proto': 'tcp', 'state': 'CON', 'label': 1,
            'attack_cat': 'Lateral Movement',
            'risk_level': 3,  # Level 3 지정
            'risk_score': random.randint(75, 89)
        })

    # 데이터 병합
    df_gen = pd.DataFrame(new_rows)
    df_final = pd.concat([df_base, df_gen], ignore_index=True).fillna(0)
    df_final['is_internal'] = 1 
    df_final['is_critical_port'] = df_final['dsport'].isin(CRITICAL_PORTS).astype(int)
    
    try:
        df_final.to_csv(SAVE_DATA_PATH, index=False)
        print(f"\n✅ 완성! 총 {len(df_final):,} 행 저장 완료.")
        print("-" * 30)
        print(f"📊 [최종 데이터 클래스 분포 확인]")
        print(df_final['risk_level'].value_counts().sort_index()) # 0, 1, 2, 3이 모두 있는지 꼭 확인!
        print("-" * 30)
    except PermissionError:
        print("\n❌ 실패: CSV 파일을 닫고 다시 실행하세요!")

if __name__ == "__main__":
    generate_4level_data()