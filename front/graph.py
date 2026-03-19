import json
import pandas as pd
import networkx as nx
from analysis import LATERAL_PORTS, risk_color, risk_label
from scapy.all import rdpcap, IP, TCP, UDP


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
    - betweenness_centrality : 공격 허브 탐지 (노드 500개 초과 시 샘플링)
    - in_degree_centrality   : 많이 공격받는 노드
    - out_degree_centrality  : 많이 공격하는 노드
    """
    metrics = {}

    # 노드 수 많으면 샘플링으로 근사 계산 (속도 최적화)
    n = G.number_of_nodes()
    if n > 500:
        k = min(100, n)  # 최대 100개 샘플로 근사
        betweenness = nx.betweenness_centrality(G, normalized=True, k=k)
    else:
        betweenness = nx.betweenness_centrality(G, normalized=True)
    in_deg  = nx.in_degree_centrality(G)
    out_deg = nx.out_degree_centrality(G)

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

    # 중복 제거, 긴 경로 우선 정렬
    paths = sorted(set(tuple(p) for p in paths), key=len, reverse=True)

    # 부분 경로 제거 — 더 긴 경로의 부분집합인 경로는 제외
    filtered = []
    for path in paths:
        path_set = set(path)
        is_subset = any(
            path_set.issubset(set(longer)) and list(path) != longer
            for longer in filtered
        )
        if not is_subset:
            filtered.append(list(path))

    return filtered  # 전체 반환 (UI에서 표시)

def pcap_to_edge_df(pcap_file):
    """
    PCAP
    """

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        raise ValueError(f"PCAP 파일을 읽을 수 없습니다: {e}")

    rows = []
    count = 0

    for pkt in packets:
        # IP 패킷만 처리
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        proto = "OTHER"
        port = 0

        if TCP in pkt:
            proto = "TCP"
            port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            port = pkt[UDP].dport

        rows.append({
            "SourceAddress": src,
            "DestAddress": dst,
            "DestPort": port,
            "Application": proto,
            "Bytes": len(pkt)
        })

        count += 1

    if not rows:
        raise ValueError("유효한 IP 패킷이 없습니다.")

    df = pd.DataFrame(rows)

    # ── 엣지 집계 ─────────────────────────────
    edge_df = (
        df.groupby(
            ["SourceAddress", "DestAddress", "DestPort", "Application"]
        )
        .agg(
            Packets=("Bytes", "count"),
            Bytes=("Bytes", "sum")
        )
        .reset_index()
    )

    return edge_df



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

    # 공격 경로 텍스트 — 스크롤 가능한 행 형태
    if paths:
        path_rows = ""
        for i, path in enumerate(paths, 1):
            hops = len(path) - 1
            path_str = " → ".join(path)
            path_rows += (
                f"<div class='path-row'>"+
                f"<span class='path-num'>{i}</span>"+
                f"<span class='path-hops'>{hops}홉</span>"+
                f"<span class='path-str'>{path_str}</span>"+
                f"</div>"
            )
        path_text = path_rows
        path_count = len(paths)
    else:
        path_text = "<div style='color:#555;padding:6px 0'>탐지된 측면이동 경로 없음</div>"
        path_count = 0

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
html,body{{height:620px;overflow:hidden;background:#0d0d1a;font-family:monospace;}}
body{{display:flex;flex-direction:column;}}
#graph{{width:100%;flex:1;min-height:0;background:#0d0d1a;border:1px solid #2a2a4a;border-radius:8px 8px 0 0;}}
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
#path-bar{{background:rgba(20,20,40,0.9);border:1px solid #2a2a4a;
  border-radius:0 0 8px 8px;font-size:11px;color:#aaa;flex-shrink:0;}}
#path-bar-header{{
  padding:8px 14px 6px;color:#FFD700;font-weight:bold;font-size:11px;
  border-bottom:1px solid #2a2a4a;display:flex;align-items:center;gap:8px;}}
#path-bar-count{{
  background:rgba(255,215,0,0.15);border:1px solid rgba(255,215,0,0.3);
  border-radius:10px;padding:1px 8px;font-size:10px;color:#FFD700;}}
#path-bar-scroll{{
  height:160px;overflow-y:auto;padding:4px 0;}}
#path-bar-scroll::-webkit-scrollbar{{width:4px;}}
#path-bar-scroll::-webkit-scrollbar-track{{background:#0d0d1a;}}
#path-bar-scroll::-webkit-scrollbar-thumb{{background:#2a2a4a;border-radius:2px;}}
.path-row{{
  display:flex;align-items:baseline;gap:8px;
  padding:3px 14px;line-height:1.6;
  border-bottom:1px solid rgba(255,255,255,0.03);}}
.path-row:hover{{background:rgba(255,215,0,0.04);}}
.path-num{{
  color:#FFD700;font-weight:bold;font-size:11px;
  flex-shrink:0;width:16px;}}
.path-hops{{
  color:#556;font-size:10px;flex-shrink:0;
  background:rgba(100,100,180,0.15);border-radius:3px;
  padding:0 5px;}}
.path-str{{color:#8899aa;font-size:11px;word-break:break-all;}}

/* 전체화면 오버레이 */
#fs-overlay{{
  display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;
  background:#0d0d1a;z-index:99999;flex-direction:column;
}}
#fs-overlay.active{{display:flex;}}
#fs-graph{{width:100%;flex:1;min-height:0;background:#0d0d1a;}}
#fs-info-panel{{position:absolute;top:12px;right:60px;background:rgba(20,20,40,0.96);
  border:1px solid #333;border-radius:8px;padding:14px 18px;width:210px;
  color:#ccc;font-size:12px;display:none;z-index:10;line-height:1.7;}}
#fs-info-panel h4{{color:#fff;margin-bottom:6px;font-size:13px;}}
#fs-btn{{
  position:absolute;top:10px;right:10px;z-index:20;
  background:rgba(112,128,255,0.2);border:1px solid #7080ff;
  border-radius:6px;padding:4px 10px;color:#7080ff;
  font-size:11px;cursor:pointer;font-family:monospace;
}}
#fs-btn:hover{{background:rgba(112,128,255,0.35);}}
#fs-close-btn{{
  position:absolute;top:12px;right:12px;z-index:100000;
  background:rgba(255,75,75,0.2);border:1px solid #FF4B4B;
  border-radius:6px;padding:6px 14px;color:#FF4B4B;
  font-size:12px;cursor:pointer;font-family:monospace;
}}
#fs-close-btn:hover{{background:rgba(255,75,75,0.35);}}
</style></head><body>
<!-- 전체화면 오버레이 -->
<div id="fs-overlay">
  <button id="fs-close-btn" onclick="closeFullscreen()">✕ 닫기 (ESC)</button>
  <div id="fs-graph"></div>
  <div id="fs-info-panel">
    <h4 id="fs-ip-title">-</h4>
    <div id="fs-risk-badge" class="risk-badge">-</div>
    <div id="fs-ip-details"></div>
  </div>
</div>
<div style="position:relative;flex:1;min-height:0;display:flex;flex-direction:column;">
  <div id="graph"></div>
  <button id="fs-btn" onclick="openFullscreen()">⛶ 꽉채우기</button>
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
<div id="path-bar">
  <div id="path-bar-header">
    🔍 탐지된 공격 경로 (NetworkX)
    <span id="path-bar-count">{path_count}개</span>
  </div>
  <div id="path-bar-scroll">{path_text}</div>
</div>
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
// 원본 색상 저장
var originalNodeColors={{}};
var originalEdgeColors={{}};
nodes.get().forEach(function(n){{
  originalNodeColors[n.id]={{
    background: n.color.background,
    border: n.color.border,
    fontColor: n.font?n.font.color:'#ffffff'
  }};
}});
edges.get().forEach(function(e){{
  originalEdgeColors[e.id]={{
    color: e.color.color,
    width: e.width,
    fontColor: e.font?e.font.color:'#aaaaaa'
  }};
}});

var selectedNode=null;

function dimAll(){{
  var nodeUpdates=[];
  var edgeUpdates=[];
  nodes.get().forEach(function(n){{
    nodeUpdates.push({{
      id:n.id,
      color:{{background:'#1a1a28',border:'#2a2a3a'}},
      font:{{color:'#333344'}}
    }});
  }});
  edges.get().forEach(function(e){{
    edgeUpdates.push({{
      id:e.id,
      color:{{color:'#1a1a28'}},
      font:{{color:'#1a1a28'}},
      width:0.5
    }});
  }});
  nodes.update(nodeUpdates);
  edges.update(edgeUpdates);
}}

function highlightNode(nodeId){{
  var connEdges=edges.get({{filter:function(e){{return e.from===nodeId||e.to===nodeId;}}}});
  var connNodeIds=new Set([nodeId]);
  connEdges.forEach(function(e){{
    connNodeIds.add(e.from);
    connNodeIds.add(e.to);
  }});
  // 연결 노드 원래 색으로
  connNodeIds.forEach(function(id){{
    var orig=originalNodeColors[id];
    if(!orig) return;
    var isSel=(id===nodeId);
    nodes.update([{{
      id:id,
      color:{{
        background: orig.background,
        border: isSel?'#ffffff':orig.border
      }},
      font:{{color:orig.fontColor}},
      borderWidth: isSel?3:1.5
    }}]);
  }});
  // 연결 엣지 원래 색으로
  connEdges.forEach(function(e){{
    var orig=originalEdgeColors[e.id];
    if(!orig) return;
    edges.update([{{
      id:e.id,
      color:{{color:orig.color}},
      font:{{color:orig.fontColor}},
      width:orig.width
    }}]);
  }});
}}

function resetAll(){{
  var nodeUpdates=[];
  var edgeUpdates=[];
  nodes.get().forEach(function(n){{
    var orig=originalNodeColors[n.id];
    if(!orig) return;
    nodeUpdates.push({{id:n.id,color:{{background:orig.background,border:orig.border}},font:{{color:orig.fontColor}},borderWidth:1.5}});
  }});
  edges.get().forEach(function(e){{
    var orig=originalEdgeColors[e.id];
    if(!orig) return;
    edgeUpdates.push({{id:e.id,color:{{color:orig.color}},font:{{color:orig.fontColor}},width:orig.width}});
  }});
  nodes.update(nodeUpdates);
  edges.update(edgeUpdates);
  selectedNode=null;
  document.getElementById('info-panel').style.display='none';
}}

network.on('click',function(p){{
  var panel=document.getElementById('info-panel');
  if(p.nodes.length>0){{
    var nodeId=p.nodes[0];
    // 같은 노드 다시 클릭하면 원상복구
    if(selectedNode===nodeId){{
      resetAll();
      return;
    }}
    selectedNode=nodeId;
    var n=nodes.get(nodeId);
    // 전체 흐리게 → 연결된 것만 강조
    dimAll();
    highlightNode(nodeId);
    // 패널 업데이트
    document.getElementById('ip-title').textContent=nodeId;
    var b=document.getElementById('risk-badge');
    b.textContent=n.risk>=0.7?'HIGH':(n.risk>=0.4?'MEDIUM':'LOW');
    b.style.background=originalNodeColors[nodeId].background;
    b.style.color='#fff';
    var ce=edges.get({{filter:function(e){{return e.from===nodeId||e.to===nodeId;}}}});
    var outbound=ce.filter(function(e){{return e.from===nodeId;}});
    var inbound=ce.filter(function(e){{return e.to===nodeId;}});
    var latOut=outbound.filter(function(e){{return originalEdgeColors[e.id]&&originalEdgeColors[e.id].width>=2.5;}}).length;
    document.getElementById('ip-details').innerHTML=
      '<br>Risk Score: <b>'+n.risk+'</b>'+
      '<br>경유 중심성: <b>'+n.betweenness+'</b>'+
      '<br>측면이동 PR: <b>'+n.lat_pagerank+'</b>'+
      '<br>발신: '+outbound.length+'건 | 수신: '+inbound.length+'건'+
      (latOut>0?'<br><span style="color:#FF4B4B">⚠️ 측면이동 발신: '+latOut+'건</span>':'')+
      '<br><br><span style="color:#555;font-size:10px">다시 클릭하거나 빈 곳 클릭 시 초기화</span>';
    panel.style.display='block';
  }}else{{
    // 빈 곳 클릭 → 원상복구
    resetAll();
  }}
}});

network.on('stabilizationIterationsDone',function(){{
  network.setOptions({{physics:{{enabled:false}}}});
  nodes.get().forEach(function(n){{
    if(n.color&&n.color.background){{
      originalNodeColors[n.id]={{
        background:n.color.background,
        border:n.color.border||'#1a1a2e',
        fontColor:n.font?n.font.color:'#ffffff'
      }};
    }}
  }});
}});

// ── 전체화면 (노드 위치 그대로 유지) ─────────────────────
var fsNetwork=null;

function openFullscreen(){{
  // 현재 노드 위치 저장
  var positions=network.getPositions();

  // 위치 정보를 노드 데이터에 고정
  var posNodes=nodes.get().map(function(n){{
    var pos=positions[n.id];
    return Object.assign({{}},n,{{
      x: pos?pos.x:n.x,
      y: pos?pos.y:n.y,
      fixed:{{x:true,y:true}}
    }});
  }});
  var fixedNodes=new vis.DataSet(posNodes);

  document.getElementById('fs-overlay').classList.add('active');
  if(fsNetwork){{ fsNetwork.destroy(); }}
  fsNetwork=new vis.Network(
    document.getElementById('fs-graph'),
    {{nodes:fixedNodes,edges:edges}},
    {{
      physics:{{enabled:false}},
      interaction:{{hover:true,tooltipDelay:80,zoomView:true,dragView:true}},
      edges:{{smooth:{{type:'curvedCW',roundness:0.15}}}},
      nodes:{{borderWidth:2}}
    }}
  );

  // 전체화면에서도 동일한 클릭 동작
  fsNetwork.on('click',function(p){{
    var panel=document.getElementById('fs-info-panel');
    if(p.nodes.length>0){{
      var nodeId=p.nodes[0];
      var n=nodes.get(nodeId);
      document.getElementById('fs-ip-title').textContent=nodeId;
      var b=document.getElementById('fs-risk-badge');
      b.textContent=n.risk>=0.7?'HIGH':(n.risk>=0.4?'MEDIUM':'LOW');
      b.style.background=originalNodeColors[nodeId]?originalNodeColors[nodeId].background:'#333';
      b.style.color='#fff';
      var ce=edges.get({{filter:function(e){{return e.from===nodeId||e.to===nodeId;}}}});
      var outbound=ce.filter(function(e){{return e.from===nodeId;}});
      var inbound=ce.filter(function(e){{return e.to===nodeId;}});
      var latOut=outbound.filter(function(e){{return originalEdgeColors[e.id]&&originalEdgeColors[e.id].width>=2.5;}}).length;
      document.getElementById('fs-ip-details').innerHTML=
        '<br>Risk Score: <b>'+n.risk+'</b>'+
        '<br>경유 중심성: <b>'+n.betweenness+'</b>'+
        '<br>측면이동 PR: <b>'+n.lat_pagerank+'</b>'+
        '<br>발신: '+outbound.length+'건 | 수신: '+inbound.length+'건'+
        (latOut>0?'<br><span style="color:#FF4B4B">⚠️ 측면이동 발신: '+latOut+'건</span>':'');
      panel.style.display='block';
    }}else{{
      panel.style.display='none';
    }}
  }});

  // 전체화면에서 뷰 맞춤
  setTimeout(function(){{ fsNetwork.fit({{animation:false}}); }},100);
}}

function closeFullscreen(){{
  document.getElementById('fs-overlay').classList.remove('active');
  document.getElementById('fs-info-panel').style.display='none';
  if(fsNetwork){{ fsNetwork.destroy(); fsNetwork=null; }}
}}

document.addEventListener('keydown',function(e){{
  if(e.key==='Escape'){{ closeFullscreen(); }}
}});
</script></body></html>"""