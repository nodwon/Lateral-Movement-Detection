import json
import pandas as pd
import networkx as nx
from analysis import LATERAL_PORTS, risk_color, risk_label


def build_networkx_graph(edge_df: pd.DataFrame) -> nx.DiGraph:
    """엣지 데이터프레임으로 NetworkX 방향 그래프 생성"""
    G = nx.DiGraph()
    for _, row in edge_df.iterrows():
        src  = row["SourceAddress"]
        dst  = row["DestAddress"]
        port = int(row["DestPort"]) if pd.notna(row["DestPort"]) else 0
        G.add_edge(src, dst,
                   port=port,
                   proto=row["Application"],
                   packets=int(row["Packets"]),
                   bytes=int(row["Bytes"]),
                   is_lateral=port in LATERAL_PORTS)
    return G


def compute_nx_metrics(G: nx.DiGraph) -> dict:
    """
    NetworkX 알고리즘으로 노드별 지표 계산
    - betweenness_centrality : 공격 허브 탐지 (경유 빈도)
    - in_degree_centrality   : 많이 공격받는 노드
    - out_degree_centrality  : 많이 공격하는 노드
    """
    metrics = {}

    betweenness = nx.betweenness_centrality(G, normalized=True)
    in_deg      = nx.in_degree_centrality(G)
    out_deg     = nx.out_degree_centrality(G)

    # 측면이동 엣지만 추출한 서브그래프
    lateral_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("is_lateral")]
    G_lat = G.edge_subgraph(lateral_edges) if lateral_edges else nx.DiGraph()

    # 측면이동 서브그래프에서 PageRank (공격 전파 중심 노드)
    try:
        lat_pagerank = nx.pagerank(G_lat, alpha=0.85) if G_lat.number_of_nodes() > 0 else {}
    except Exception:
        lat_pagerank = {}

    for node in G.nodes():
        metrics[node] = {
            "betweenness":   round(betweenness.get(node, 0), 4),
            "in_degree":     round(in_deg.get(node, 0), 4),
            "out_degree":    round(out_deg.get(node, 0), 4),
            "lat_pagerank":  round(lat_pagerank.get(node, 0), 4),
            "lateral_out":   sum(1 for _, v, d in G.out_edges(node, data=True) if d.get("is_lateral")),
        }
    return metrics


def find_attack_paths(G: nx.DiGraph) -> list:
    """
    측면이동 엣지만으로 공격 경로 탐지
    외부 IP → 내부 IP 최장 경로 추출
    """
    lateral_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("is_lateral")]
    if not lateral_edges:
        return []

    G_lat = nx.DiGraph()
    G_lat.add_edges_from(lateral_edges)

    # 외부 IP (진입점) 찾기
    def is_external(ip):
        return (not str(ip).startswith("192.168") and
                not str(ip).startswith("10.") and
                not str(ip).startswith("172."))

    entry_nodes = [n for n in G_lat.nodes() if is_external(n)]
    paths = []

    for entry in entry_nodes:
        try:
            # 진입점에서 도달 가능한 모든 노드까지 경로
            for target in nx.descendants(G_lat, entry):
                try:
                    path = nx.shortest_path(G_lat, entry, target)
                    if len(path) >= 3:  # 최소 3홉 이상만
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
        except Exception:
            continue

    # 중복 제거, 긴 경로 우선
    paths = sorted(set(tuple(p) for p in paths), key=len, reverse=True)
    return [list(p) for p in paths[:3]]  # 상위 3개만


def build_graph_html(edge_df: pd.DataFrame, risk_scores: dict) -> str:
    """NetworkX 분석 결과를 vis.js로 시각화"""

    # ── NetworkX 분석 ──────────────────────────────────────────────
    G       = build_networkx_graph(edge_df)
    metrics = compute_nx_metrics(G)
    paths   = find_attack_paths(G)

    # 공격 경로에 포함된 엣지 표시용
    path_edges = set()
    for path in paths:
        for i in range(len(path) - 1):
            path_edges.add((path[i], path[i+1]))

    # ── 노드 생성 ──────────────────────────────────────────────────
    nodes = []
    for ip in G.nodes():
        score = risk_scores.get(ip, 0)
        color = risk_color(score)
        m     = metrics.get(ip, {})

        is_external = (not str(ip).startswith("192.168") and
                       not str(ip).startswith("10.") and
                       not str(ip).startswith("172."))

        # 중심성 높을수록 노드 크게 (공격 허브 강조)
        centrality_boost = m.get("betweenness", 0) * 40
        size = 18 + score * 28 + centrality_boost

        # 공격 경로 허브 노드는 별 모양
        in_path = any(ip in path for path in paths)
        shape   = "star" if in_path and not is_external else ("diamond" if is_external else "dot")

        tooltip = (
            f"<b>{ip}</b><br>"
            f"위험도: {risk_label(score)} ({score})<br>"
            f"{'[외부 IP]' if is_external else '[내부 IP]'}<br>"
            f"─────────────────<br>"
            f"📊 NetworkX 중심성 지표<br>"
            f"경유 중심성(Betweenness): {m.get('betweenness', 0):.4f}<br>"
            f"수신 중심성(In-degree): {m.get('in_degree', 0):.4f}<br>"
            f"발신 중심성(Out-degree): {m.get('out_degree', 0):.4f}<br>"
            f"측면이동 PageRank: {m.get('lat_pagerank', 0):.4f}<br>"
            f"─────────────────<br>"
            f"측면이동 발신: {m.get('lateral_out', 0)}건"
            + (f"<br>⭐ 공격 경로 포함" if in_path else "")
        )

        nodes.append({
            "id":    ip,
            "label": ip,
            "color": {
                "background": color,
                "border": "#ffffff" if in_path else "#1a1a2e",
                "highlight": {"background": color, "border": "#ffffff"}
            },
            "borderWidth": 3 if in_path else 1.5,
            "size":  size,
            "font":  {"color": "#ffffff", "size": 12, "face": "monospace"},
            "shape": shape,
            "title": tooltip,
            "risk":  score,
            "betweenness": m.get("betweenness", 0),
            "lat_pagerank": m.get("lat_pagerank", 0),
        })

    # ── 엣지 생성 ──────────────────────────────────────────────────
    edges = []
    for _, row in edge_df.iterrows():
        port = int(row["DestPort"]) if pd.notna(row["DestPort"]) else 0
        proto = row["Application"]
        is_lateral  = port in LATERAL_PORTS
        is_path_edge = (row["SourceAddress"], row["DestAddress"]) in path_edges

        # 공격 경로 엣지는 노란색 강조
        if is_path_edge:
            edge_color = "#FFD700"
            width = 4
        elif is_lateral:
            edge_color = "#FF4B4B"
            width = 2.5
        else:
            edge_color = "#334466"
            width = 1

        edges.append({
            "from":   row["SourceAddress"],
            "to":     row["DestAddress"],
            "label":  f"{proto}:{port}" if is_lateral else "",
            "color":  {"color": edge_color, "highlight": "#ffffff"},
            "width":  width,
            "dashes": not is_lateral and not is_path_edge,
            "arrows": "to",
            "title": (
                f"<b>{row['SourceAddress']} → {row['DestAddress']}</b><br>"
                f"Protocol: {proto} (Port {port})<br>"
                f"Packets: {int(row['Packets'])} | Bytes: {int(row['Bytes']):,}<br>"
                f"{'🟡 공격 경로 엣지' if is_path_edge else ('⚠️ 측면이동 의심' if is_lateral else '일반 트래픽')}"
            ),
            "font": {"color": "#ffdd88" if is_path_edge else "#ffaaaa", "size": 10, "strokeWidth": 0},
        })

    nodes_json = json.dumps(nodes, ensure_ascii=False)
    edges_json = json.dumps(edges, ensure_ascii=False)

    # 공격 경로 텍스트
    path_text = ""
    for i, path in enumerate(paths, 1):
        path_text += f"경로 {i}: {' → '.join(path)}<br>"
    if not path_text:
        path_text = "탐지된 측면이동 경로 없음"

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#0d0d1a;font-family:monospace;}}
#graph{{width:100%;height:440px;background:#0d0d1a;border:1px solid #2a2a4a;border-radius:8px;}}
.vis-tooltip{{background:#1a1a2e !important;color:#fff !important;border:1px solid #444 !important;
  border-radius:6px !important;padding:8px 12px !important;font-size:12px !important;
  font-family:monospace !important;max-width:300px;line-height:1.6;}}
#info-panel{{position:absolute;top:12px;right:12px;background:rgba(20,20,40,0.96);
  border:1px solid #333;border-radius:8px;padding:14px 18px;width:210px;
  color:#ccc;font-size:12px;display:none;z-index:10;line-height:1.7;}}
#info-panel h4{{color:#fff;margin-bottom:6px;font-size:13px;}}
.risk-badge{{display:inline-block;padding:2px 10px;border-radius:12px;
  font-weight:bold;font-size:11px;margin-bottom:6px;}}
.legend{{position:absolute;bottom:12px;left:12px;background:rgba(20,20,40,0.92);
  border:1px solid #333;border-radius:8px;padding:10px 14px;color:#ccc;font-size:11px;z-index:10;}}
.legend-item{{display:flex;align-items:center;gap:8px;margin:3px 0;}}
.dot{{width:9px;height:9px;border-radius:50%;flex-shrink:0;}}
#path-bar{{background:rgba(20,20,40,0.9);border:1px solid #2a2a4a;border-radius:0 0 8px 8px;
  padding:8px 14px;font-size:11px;color:#aaa;line-height:1.8;}}
#path-bar b{{color:#FFD700;}}
</style></head><body>
<div style="position:relative">
  <div id="graph"></div>
  <div id="info-panel">
    <h4 id="ip-title">-</h4>
    <div id="risk-badge" class="risk-badge">-</div>
    <div id="ip-details"></div>
  </div>
  <div class="legend">
    <div style="color:#fff;font-weight:bold;margin-bottom:5px">위험도</div>
    <div class="legend-item"><div class="dot" style="background:#FF4B4B"></div>HIGH</div>
    <div class="legend-item"><div class="dot" style="background:#FFA500"></div>MEDIUM</div>
    <div class="legend-item"><div class="dot" style="background:#00CC88"></div>LOW</div>
    <div style="color:#fff;font-weight:bold;margin:6px 0 4px">엣지</div>
    <div class="legend-item"><div style="width:18px;height:3px;background:#FFD700;flex-shrink:0"></div>공격 경로</div>
    <div class="legend-item"><div style="width:18px;height:2px;background:#FF4B4B;flex-shrink:0"></div>측면이동 포트</div>
    <div class="legend-item"><div style="width:18px;height:1px;border-top:1px dashed #334466;flex-shrink:0"></div>일반 트래픽</div>
    <div style="color:#fff;font-weight:bold;margin:6px 0 4px">노드 모양</div>
    <div class="legend-item"><span style="color:#FFD700;font-size:13px">★</span> 공격 경로 노드</div>
    <div class="legend-item"><span style="font-size:11px">◆</span> 외부 IP</div>
  </div>
</div>
<div id="path-bar"><b>🔍 탐지된 공격 경로 (NetworkX)</b><br>{path_text}</div>
<script>
var nodes=new vis.DataSet({nodes_json});
var edges=new vis.DataSet({edges_json});
var network=new vis.Network(document.getElementById('graph'),{{nodes,edges}},{{
  physics:{{
    enabled:true,
    barnesHut:{{gravitationalConstant:-7000,springLength:200,springConstant:0.03,damping:0.2}},
    stabilization:{{iterations:300}}
  }},
  interaction:{{hover:true,tooltipDelay:80,zoomView:true,dragView:true}},
  edges:{{smooth:{{type:'curvedCW',roundness:0.15}}}},
  nodes:{{borderWidth:2}}
}});
network.on('click',function(p){{
  var panel=document.getElementById('info-panel');
  if(p.nodes.length>0){{
    var nodeId=p.nodes[0];
    var n=nodes.get(nodeId);
    document.getElementById('ip-title').textContent=nodeId;
    var b=document.getElementById('risk-badge');
    b.textContent=n.risk>=0.7?'HIGH':(n.risk>=0.4?'MEDIUM':'LOW');
    b.style.background=n.color.background;b.style.color='#fff';
    var ce=edges.get({{filter:e=>e.from===nodeId||e.to===nodeId}});
    var outbound=ce.filter(e=>e.from===nodeId);
    var inbound=ce.filter(e=>e.to===nodeId);
    var latOut=outbound.filter(e=>e.width>=2.5).length;
    document.getElementById('ip-details').innerHTML=
      '<br>Risk Score: <b>'+n.risk+'</b>'+
      '<br>경유 중심성: <b>'+n.betweenness+'</b>'+
      '<br>측면이동 PR: <b>'+n.lat_pagerank+'</b>'+
      '<br>발신: '+outbound.length+'건 | 수신: '+inbound.length+'건'+
      (latOut>0?'<br><span style="color:#FF4B4B">⚠️ 측면이동 발신: '+latOut+'건</span>':'');
    panel.style.display='block';
  }}else{{panel.style.display='none';}}
}});
network.on('stabilizationIterationsDone',function(){{
  network.setOptions({{physics:{{enabled:false}}}});
}});
</script></body></html>"""
