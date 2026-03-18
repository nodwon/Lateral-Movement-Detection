import pandas as pd
import numpy as np

# 1. 파일 경로 설정
file_path

def analyze_phase1_data(path):
    print(f"📂 데이터를 불러오는 중: {path}")
    try:
        # 데이터 읽기 (용량이 클 수 있으니 상위 10만 줄만 먼저 봐도 좋습니다)
        df = pd.read_csv(path, nrows=5000000) 
        
        # 컬럼명 정리 (공백 제거 및 소문자화)
        df.columns = [col.strip().lower() for col in df.columns]
        
        print(f"✅ 총 {len(df)}개의 로그를 성공적으로 읽었습니다.")
        print(f"📊 포함된 정보(컬럼): {df.columns.tolist()}")

        # 2. 핵심 컬럼 자동 매칭
        # 출발지(src), 목적지(dst), 라벨(label) 컬럼을 찾습니다.
        src_ip = [c for c in df.columns if 'src' in c or 'source' in c][0]
        dst_ip = [c for c in df.columns if 'dst' in c or 'destination' in c][0]
        label_col = [c for c in df.columns if 'label' in c or 'target' in c or 'class' in c][0]

        # 3. 수평 이동(Lateral Movement) 지표 분석
        # 지표 A: 한 IP가 얼마나 많은 곳을 찔러봤나? (공격자의 전형적인 특징)
        fan_out = df.groupby(src_ip)[dst_ip].nunique().sort_values(ascending=False)
        top_attacker_candidate = fan_out.index[0]
        max_conn = fan_out.max()

        # 지표 B: 공격 데이터의 비율 (학습이 가능한 수준인가?)
        attack_count = len(df[df[label_col] != 0]) # 0이 아닌 것을 공격으로 간주
        attack_ratio = (attack_count / len(df)) * 100

        # 4. 품질 점수 계산 (100점 만점)
        # - 공격 비율이 5~30% 사이면 가산점
        # - 특정 IP의 연결 수(Fan-out)가 10개 이상이면 가산점
        score = 0
        if 5 <= attack_ratio <= 40: score += 50
        elif attack_ratio > 0: score += 20
        
        if max_conn >= 20: score += 50
        elif max_conn >= 5: score += 20
        
        # [추가 제안 로직] 내부망 통신 비중 체크
        internal_prefix = '149.171.' # 프로젝트에서 사용하는 내부 IP 대역
        internal_df = df[df[src_ip].str.startswith(internal_prefix) & df[dst_ip].str.startswith(internal_prefix)]

        internal_ratio = (len(internal_df) / len(df)) * 100
        print(f"🏠 내부망 간 통신(East-West) 비중: {internal_ratio:.2f}%")

        if internal_ratio < 10:
            print("⚠️ 주의: 전체 데이터 중 내부 통신 비중이 너무 낮습니다. 그래프 학습이 어려울 수 있습니다.")
        # 5. 결과 보고
        print("\n" + "="*50)
        print(f"💎 데이터 품질 분석 결과: {score}점 / 100점")
        print("="*50)
        print(f"🚩 탐지된 공격 데이터 비율: {attack_ratio:.2f}%")
        print(f"🚩 최대 확산 IP ({top_attacker_candidate}): {max_conn}개 서버 접속")
        print("-" * 50)

        if score >= 80:
            print("🟢 [판정] 아주 좋은 데이터입니다! 당장 프로젝트에 사용하세요.")
        elif score >= 50:
            print("🟡 [판정] 보통입니다. 공격 데이터 비중이 적으니 가중치를 조절해야 합니다.")
        else:
            print("🔴 [판정] 부족합니다. 수평 이동 패턴이 너무 약합니다.")
        
        return df

    except Exception as e:
        print(f"❌ 에러 발생: {e}")
        return None

# 실행
df = analyze_phase1_data(file_path)