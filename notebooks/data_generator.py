import pandas as pd
import numpy as np
import random
import os

# [파일 경로 설정]
BASE_DATA_PATH 
SAVE_DATA_PATH 
# 회사 내부망 주요 감시 포트 (대시보드 시각화용)
CRITICAL_PORTS = [445, 3389, 22, 5985, 135, 5900, 1433, 80, 21, 23, 8080]

# ---------------------------------------------------------
# 1. 20가지 정교한 공격 시나리오 정의 (절대 안 까먹었습니다!)
# ---------------------------------------------------------
def get_attack_scenarios():
    return [
        {"name": "SMB_PsExec", "port": 445, "dur": (0.1, 1.2), "sbytes": (5000, 15000)},
        {"name": "SMB_Exfil", "port": 445, "dur": (10, 120), "sbytes": (100000, 500000)},
        {"name": "RDP_Brute", "port": 3389, "dur": (0.01, 0.3), "sbytes": (500, 3000)},
        {"name": "RDP_Session", "port": 3389, "dur": (600, 3600), "sbytes": (500000, 2000000)},
        {"name": "SSH_Scan", "port": 22, "dur": (0.01, 0.6), "sbytes": (200, 1000)},
        {"name": "SSH_Pivoting", "port": 22, "dur": (60, 900), "sbytes": (20000, 80000)},
        {"name": "WinRM_Cmd", "port": 5985, "dur": (1.0, 8.0), "sbytes": (1500, 6000)},
        {"name": "SQL_Discovery", "port": 1433, "dur": (0.2, 3.0), "sbytes": (3000, 15000)},
        {"name": "WMI_Lateral", "port": 135, "dur": (0.5, 5.0), "sbytes": (4000, 18000)},
        {"name": "VNC_Access", "port": 5900, "dur": (300, 1800), "sbytes": (100000, 600000)},
        {"name": "FTP_Infil", "port": 21, "dur": (5, 60), "sbytes": (30000, 150000)},
        {"name": "Telnet_Recon", "port": 23, "dur": (1, 15), "sbytes": (800, 5000)},
        {"name": "SNMP_Enum", "port": 161, "dur": (0.1, 2.0), "sbytes": (300, 2000)},
        {"name": "HTTP_Internal", "port": 80, "dur": (2, 30), "sbytes": (6000, 30000)},
        {"name": "Oracle_TNS", "port": 1521, "dur": (1, 10), "sbytes": (4000, 20000)},
        {"name": "Redis_Exploit", "port": 6379, "dur": (0.2, 2.0), "sbytes": (2000, 8000)},
        {"name": "Postgres_Scan", "port": 5432, "dur": (1.0, 4.0), "sbytes": (3000, 12000)},
        {"name": "LDAP_Enum", "port": 389, "dur": (1.0, 15.0), "sbytes": (8000, 35000)},
        {"name": "SMB_Ghost", "port": 445, "dur": (0.1, 0.5), "sbytes": (1000, 4000)},
        {"name": "Custom_Trojan", "port": 8080, "dur": (30, 300), "sbytes": (20000, 80000)},
    ]

# ---------------------------------------------------------
# 2. 데이터 생성 로직 (5-Hop 보장 + 내부망 특화)
# ---------------------------------------------------------
def generate_advanced_data():
    print("🏢 [내부망 동적 시나리오] 20가지 패턴 + 5-Hop 연쇄 주입 시작...")
    
    if not os.path.exists(BASE_DATA_PATH):
        print(f"❌ 원본 파일을 찾을 수 없습니다: {BASE_DATA_PATH}"); return

    df_base = pd.read_csv(BASE_DATA_PATH, low_memory=False)
    scenarios = get_attack_scenarios()
    
    internal_ips = [f'149.171.1.{i}' for i in range(1, 255)]
    new_rows = []
    current_time = 1421927400
    target_count = 100000 

    # [Scenario A] 5~10단계 연쇄 이동 (70%)
    print("🔗 5-Hop 이상 연쇄 경로 강제 생성 중 (20패턴 적용)...")
    while len(new_rows) < (target_count * 0.7):
        chain_len = random.randint(5, 10) 
        path = random.sample(internal_ips, chain_len + 1)
        chain_time = current_time + random.randint(0, 100000)
        
        for i in range(len(path) - 1):
            s = random.choice(scenarios) # 20가지 중 하나 무작위 선택
            chain_time += random.randint(120, 600)
            
            new_rows.append({
                'srcip': path[i], 'dstip': path[i+1], 'dsport': s['port'],
                'dur': random.uniform(*s['dur']), 
                'sbytes': random.randint(*s['sbytes']),
                'dbytes': random.randint(*s['sbytes']) // 2,
                'stime': chain_time, 'ltime': chain_time + 1,
                'proto': 'tcp', 'state': 'CON', 'label': 1,
                'attack_cat': 'Worms', 'risk_level': 5,
                'risk_score': random.randint(90, 100) # 연쇄 이동은 최상위 위험
            })

    # [Scenario B] 내부망 단발성 공격 (30%)
    print("🎯 단발성 내부망 공격 추가 중...")
    while len(new_rows) < target_count:
        s = random.choice(scenarios)
        attack_time = current_time + random.randint(0, 200000)
        new_rows.append({
            'srcip': random.choice(internal_ips), 'dstip': random.choice(internal_ips),
            'dsport': s['port'], 'dur': random.uniform(*s['dur']),
            'sbytes': random.randint(*s['sbytes']), 'dbytes': random.randint(*s['sbytes']) // 2,
            'stime': attack_time, 'ltime': attack_time + 1,
            'proto': 'tcp', 'state': 'CON', 'label': 1,
            'attack_cat': 'Lateral Movement', 'risk_level': 5,
            'risk_score': random.randint(80, 89)
        })

    # 3. 데이터 결합 및 대시보드 피처 생성
    df_gen = pd.DataFrame(new_rows)
    df_final = pd.concat([df_base, df_gen], ignore_index=True).fillna(0)
    
    print("🛠️ 대시보드 전용 지표(Critical Port, Score, Internal) 추가 중...")
    df_final['is_internal'] = 1 
    df_final['is_critical_port'] = df_final['dsport'].isin(CRITICAL_PORTS).astype(int)
    
    # 기존 데이터의 risk_score 보정
    mask = df_final['risk_score'] == 0
    df_final.loc[mask, 'risk_score'] = df_final.loc[mask, 'risk_level'].apply(
        lambda x: random.randint(0, 15) if x == 0 else
                  random.randint(20, 45) if x == 1 else
                  random.randint(45, 65) if x == 2 else
                  random.randint(65, 80) if x == 3 else random.randint(80, 85)
    )

    # 4. 저장
    try:
        df_final.to_csv(SAVE_DATA_PATH, index=False)
        print(f"\n✅ 성공! 20개 패턴이 적용된 {len(df_final):,}행 데이터 저장 완료.")
    except PermissionError:
        print("\n❌ 에러: CSV를 닫고 다시 실행해 주세요!")

if __name__ == "__main__":
    generate_advanced_data()