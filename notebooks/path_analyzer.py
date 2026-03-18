import pandas as pd
import networkx as nx
import joblib
import os

def analyze_stepping_stones():
    # 1. 경로 설정 (유저님의 환경 반영)
    BASE_DIR
    CSV_PATH 
    
    print("📂 보안 모델 및 로그 데이터를 불러오는 중...")
    try:
        model = joblib.load(os.path.join(BASE_DIR, 'xgboost_lm_final.pkl'))
        feat_encoders = joblib.load(os.path.join(BASE_DIR, 'feature_encoders.pkl'))
        df = pd.read_csv(CSV_PATH, low_memory=False)
        print("✅ 데이터 로드 완료.")
    except Exception as e:
        print(f"❌ 로드 실패: {e}"); return

    # 2. 전처리 및 예측
    drop_cols = ['srcip', 'dstip', 'sport', 'stime', 'ltime', 'attack_cat', 'label', 'risk_level', 'risk_score']
    X_input = df.drop(columns=[c for c in drop_cols if c in df.columns])

    for col, le in feat_encoders.items():
        X_input[col] = X_input[col].astype(str).map(
            lambda s: le.transform([s])[0] if s in le.classes_ else -1
        )

    df['pred_level'] = model.predict(X_input)
    attack_logs = df[df['pred_level'] == 5].copy()
    
    # 3. 그래프 생성 (방향성 그래프)
    G = nx.DiGraph()
    for _, row in attack_logs.iterrows():
        G.add_edge(row['srcip'], row['dstip'])

    # 4. 7-Hop 이상 체인 탐색 및 노드 분석
    print("\n" + "="*60)
    print("🛡️ [수평 이동 공격 체인 및 중간 노드 분석 보고서]")
    print("="*60)

    found_chains = []
    # 모든 단순 경로 탐색
    for source in [n for n, d in G.in_degree() if d == 0]: # 시작점
        for target in G.nodes():
            if source == target: continue
            try:
                for path in nx.all_simple_paths(G, source=source, target=target, cutoff=15):
                    if len(path) >= 7:
                        found_chains.append(path)
            except: continue

    print(f"📈 총 탐지된 치명적 연쇄 공격(7-Hop+): {len(found_chains)}건")
    print("-" * 60)

    # 5. 각 체인별 상세 리스트 출력
    for i, path in enumerate(found_chains):
        start_node = path[0]        # 최초 침투지 (Patient Zero)
        end_node = path[-1]         # 최종 타겟
        intermediate_nodes = path[1:-1]  # 중간 거점 (Stepping Stones)

        print(f"▶ [공격 체인 #{i+1}]")
        print(f"   - 전체 경로: {' -> '.join(path)}")
        print(f"   - 노드 수: {len(path)}개")
        print(f"   - 최초 침투지: {start_node}")
        print(f"   - 중간 거점 노드 ({len(intermediate_nodes)}개): {intermediate_nodes}")
        print(f"   - 최종 타겟: {end_node}")
        print("-" * 60)

    if not found_chains:
        print("💡 분석 결과: 7단계 이상의 연쇄 이동 경로가 발견되지 않았습니다.")

if __name__ == "__main__":
    analyze_stepping_stones()