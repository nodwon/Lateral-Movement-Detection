import pandas as pd
import networkx as nx  # 그래프 탐색을 위한 강력한 라이브러리

# ==========================================================
# 🛡️ [Step 9] 7-Hop 이상 연쇄 이동 경로(Path) 추출 및 시각화용 데이터 준비
# ==========================================================

def trace_multi_hop_paths(augmented_attack_logs, min_nodes=7):
    """
    augmented_attack_logs: 원본 IP와 모델 예측 결과(pred_level)가 합쳐진 데이터프레임
    min_nodes: 추출할 체인의 최소 노드 수 (7-Node 이상)
    """
    # 1. 시간순 정렬 (연쇄 추적을 위해 필수! stime 컬럼 활용)
    # UNSW-NB15의 stime은 Unix 타임스탬프이므로 보기 좋게 변환합니다.
    print("⏳ 공격 로그 시간순 정렬 및 시각화 데이터 가공 중...")
    attack_logs = augmented_attack_logs.sort_values(by='stime').copy()
    attack_logs['time_readable'] = pd.to_datetime(attack_logs['stime'], unit='s')
    
    # 2. Directed Graph (방향성 그래프) 생성
    # 노드: IP, 엣지: 공격 행위 (시간과 포트 정보 저장)
    G = nx.DiGraph()
    for _, row in attack_logs.iterrows():
        # 동일 IP 간의 루프 방지 및 중복 엣지 처리
        if row['srcip'] != row['dstip']:
            G.add_edge(row['srcip'], row['dstip'], 
                       time=row['time_readable'], port=row['dsport'])

    # 3. 7-Hop 이상의 긴 체인만 탐색 (DFS 기반 경로 탐색)
    print(f"🔗 {min_nodes}-Node 이상의 연쇄 이동 체인 탐색 중...")
    long_chains = []
    
    # 최초 침투지(Patient Zero) 후보군: 나에게 들어온 공격은 없고 나가기만 한 노드
    potential_sources = [n for n, d in G.in_degree() if d == 0 and G.out_degree(n) > 0]
    
    for source in potential_sources:
        # DFS를 이용해 소스 노드부터 닿을 수 있는 모든 단순 경로 탐색
        for target in G.nodes():
            if source == target: continue
            
            # 소스와 타겟 사이의 모든 단순 경로 찾기
            for path in nx.all_simple_paths(G, source=source, target=target):
                if len(path) >= min_nodes:
                    # 4. 시간 순서 검증 (A->B 시간 < B->C 시간 인지 확인)
                    is_time_ordered = True
                    edge_details = []
                    
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i+1]
                        # NetworkX는 중복 엣지를 기본으로 지원하지 않으므로, 
                        # 실제 연쇄 이동에서는 첫 번째로 발생한 시간차만 고려하는 한계가 있음.
                        # (G = nx.MultiDiGraph()를 쓰면 해결되나 로직이 복잡해짐)
                        edge_data = G.get_edge_data(u, v)
                        edge_details.append(f"({edge_data['port']}포트, {edge_data['time'].strftime('%H:%M:%S')})")
                        
                        # 다음 단계의 공격 시간이 이전 단계보다 빠르면 연쇄가 아님
                        if i > 0:
                            prev_time = G.get_edge_data(path[i-1], path[i])['time']
                            if edge_data['time'] < prev_time:
                                is_time_ordered = False
                                break
                    
                    if is_time_ordered:
                        long_chains.append({
                            'path': path,
                            'details': edge_details,
                            'start_time': G.get_edge_data(path[0], path[1])['time']
                        })

    # 5. 결과 출력
    print("\n" + "🛑" * 20)
    print(f"🚩 탐지된 {min_nodes}-Node 이상 연쇄 이동 체인: {len(long_chains)}건")
    print("🛑" * 20)
    
    for i, chain in enumerate(long_chains):
        print(f"\n[체인 #{i+1}] (시작 시간: {chain['start_time'].strftime('%H:%M:%S')})")
        
        path_str = ""
        for j in range(len(chain['path'])):
            path_str += f"[{chain['path'][j]}]"
            if j < len(chain['details']):
                path_str += f" --{chain['details'][j]}--> "
        print(path_str)
        
    return long_chains, G

# ==========================================================
# 실행 (이전 단계에서 얻은 attack_df 활용)
# ==========================================================
# G는 나중에 그래프 시각화(NetworkX)에 그대로 사용할 수 있습니다.
final_chains, attack_graph = trace_multi_hop_paths(attack_df, min_nodes=7)