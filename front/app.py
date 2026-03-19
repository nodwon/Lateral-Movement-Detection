import os
import base64
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from io import BytesIO
from ai_agent import SecurityAIAgent
from analysis import (
    load_csv, load_pcap, aggregate_edges, compute_risk,
    risk_label, build_data_summary, LATERAL_PORTS
)
from graph import (build_graph_html, pcap_to_edge_df)
from chatbot import chat_with_data
from sample_data import generate_sample_data

# ── 페이지 설정  ───────────────────────
st.set_page_config(
    page_title="측면 공격 시각화",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

@st.cache_resource
def load_agent():
    return SecurityAIAgent()

agent = load_agent()

load_dotenv()
def get_api_key() -> str:
    return os.getenv("OPENAI_API_KEY") or st.secrets.get("OPENAI_API_KEY", "")

def get_logo_b64() -> str:
    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""

LOGO_B64 = get_logo_b64()

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600&display=swap');
* {{ font-family: 'Noto Sans KR', sans-serif; }}

/* ── 기본 배경 ── */
[data-testid="stAppViewContainer"] {{ background: #e8b4a0; }}
[data-testid="stHeader"]           {{ background: transparent; }}
[data-testid="stSidebar"]          {{ background: #d9a090 !important; }}

/* ── 업로드 화면 사이드바 토글 숨김 ── */
[data-testid="stSidebarCollapsedControl"] {{ display: none !important; }}

/* ── 로고 고정 ── */
.logo-fixed {{ position: fixed; bottom: 28px; left: 28px; z-index: 99999; opacity: 0.92; }}
.logo-fixed img {{ width: 100px; filter: drop-shadow(0 2px 6px rgba(0,0,0,0.15)); }}

/* ── 타이틀 ── */
.main-title {{ font-size: 22px; font-weight: 600; color: #3a2a22; padding: 44px 0 28px; letter-spacing: 3px; text-align: center; }}

/* ── 분석 화면 ── */
.metric-card {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 10px; padding: 14px 18px; text-align: center; }}
.metric-card .label {{ color: #888; font-size: 12px; margin-bottom: 4px; }}
.metric-card .value {{ color: #fff; font-size: 26px; font-weight: bold; }}
.section-title {{ color: #7080ff; font-size: 12px; font-weight: bold; letter-spacing: 2px; text-transform: uppercase; margin: 14px 0 8px; }}

/* ── 챗봇 말풍선 ── */
.chat-user {{ background: #1e2a4a; border-radius: 12px 12px 2px 12px; padding: 11px 15px; margin: 6px 0; color: #e0e0ff; font-size: 14px; margin-left: 6%; line-height: 1.6; }}
.chat-bot {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 12px 12px 12px 2px; padding: 11px 15px; margin: 6px 0; color: #ccc; font-size: 14px; margin-right: 6%; line-height: 1.6; }}
</style>
{"" if not LOGO_B64 else f'<div class="logo-fixed"><img src="data:image/png;base64,{LOGO_B64}"/></div>'}
""", unsafe_allow_html=True)

if "page" not in st.session_state: st.session_state["page"] = "upload"
if "chat_history" not in st.session_state: st.session_state["chat_history"] = []
if "is_thinking" not in st.session_state: st.session_state["is_thinking"] = False
if "guide_shown" not in st.session_state: st.session_state["guide_shown"] = False

@st.dialog("📖 네트워크 그래프 읽는 법", width="large")
def show_graph_guide():
    st.markdown("**노드 색상**")
    st.markdown("노드 색상은 해당 IP의 위험도를 나타냅니다.")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.error("🔴 HIGH — AI 모델 또는 룰 기반 분석에서 고위험으로 분류된 IP")
    with col2:
        st.warning("🟠 MEDIUM — 의심 행동이 감지된 IP")
    with col3:
        st.success("🟢 LOW — 현재 정상 범위의 IP")

    st.markdown("**노드 모양**")
    st.markdown("⭐ 별 모양은 NetworkX가 탐지한 공격 경로 위의 노드이고, ◆ 다이아몬드는 외부 IP(내부망 아님)입니다.")

    st.divider()

    st.markdown("**노드 크기 — 경유 중심성(Betweenness)**")
    st.markdown("""
노드가 **클수록** 다른 IP들 사이의 **중간 다리 역할**을 많이 한다는 뜻입니다.
예를 들어 A→B→C 경로에서 B는 A와 C를 이어주는 중간 경유지입니다.
공격자가 내부망을 이동할 때 반드시 거치는 **피벗 포인트** IP가 크게 표시됩니다.
""")

    st.divider()

    st.markdown("**측면이동 PageRank**")
    st.markdown("""
노드 클릭 시 표시되는 **측면이동 PR** 수치는 SMB·RDP·SSH 등 **측면이동 의심 포트로만 이뤄진 연결**에서
얼마나 중심적인 전파 허브인지를 나타냅니다.

구글 검색 순위와 같은 원리로, 많은 내부 IP로 측면이동 트래픽을 퍼뜨릴수록 높은 점수를 받습니다.
**값이 높을수록** 감염을 확산시키는 핵심 허브일 가능성이 높습니다.
""")

    st.divider()

    st.markdown("**연결선(엣지)**")
    st.markdown("""
- 🟡 **노란선** — NetworkX가 탐지한 공격 경로
- 🔴 **빨간선** — 측면이동 의심 포트(SMB, RDP, SSH 등) 사용 연결
- ⬜ **회색 점선** — 일반 트래픽
""")

    st.divider()

    st.markdown("**조작법**")
    st.markdown("""
- 노드를 **클릭**하면 연결된 노드만 강조되고 상세 정보가 표시됩니다
- 같은 노드를 다시 클릭하거나 빈 곳을 클릭하면 초기화됩니다
- **스크롤**로 확대·축소, **드래그**로 화면 이동이 가능합니다
- **⛶ 꽉채우기** 버튼으로 그래프를 화면 전체로 볼 수 있습니다
""")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("✅ 확인했습니다", use_container_width=True):
        st.session_state["guide_shown"] = True
        st.rerun()


def go_home():
    st.session_state["page"] = "upload"
    st.session_state["df"] = None
    st.session_state["chat_history"] = []
    st.rerun()

def load_analysis(df):
    edge_df = aggregate_edges(df)
    risk_scores = compute_risk(df)
    
    # DestPort 안전 검사 (딕셔너리 키 매칭)
    df_temp = df.copy()
    if "DestPort" in df_temp.columns:
        df_temp["DestPort"] = pd.to_numeric(df_temp["DestPort"], errors='coerce')
        # LATERAL_PORTS가 딕셔너리이므로 .keys()를 사용해야 함
        lateral_df = df_temp[df_temp["DestPort"].isin(list(LATERAL_PORTS.keys()))]
    else:
        lateral_df = pd.DataFrame()
        
    high_risk = [ip for ip, s in risk_scores.items() if s >= 0.7]
    summary = build_data_summary(df, risk_scores)
    return edge_df, risk_scores, lateral_df, high_risk, summary

# ── 페이지 1: 업로드 ──────────────────────────────────────────────
def upload_page():
    st.markdown('<div class="main-title">측면 공격 시각화</div>', unsafe_allow_html=True)
    _, mid_col, _ = st.columns([1, 1.4, 1])
    with mid_col:
        uploaded = st.file_uploader("파일 업로드", type=["csv", "pcap", "pcapng"], label_visibility="collapsed")
        if st.button("🧪 샘플 데이터로 실행해보기", use_container_width=True):
            df = generate_sample_data()
            st.session_state["df"] = df
            st.session_state["ml_result"] = agent.analyze(df)
            st.session_state["page"] = "attack"
            st.rerun()
        if uploaded:
            with st.spinner("📡 분석 중..."):
                try:
                    df = load_pcap(uploaded) if uploaded.name.endswith(('pcap', 'pcapng')) else load_csv(uploaded)
                    st.session_state["df"] = df
                    
                    ml_result = agent.analyze(df)
                    
                    # 룰 기반 탐지 추가 (AI가 놓쳐도 포트가 위험하면 잡음)
                    is_rule_detected = False
                    if "DestPort" in df.columns:
                        ports = pd.to_numeric(df["DestPort"], errors='coerce')
                        is_rule_detected = any(ports.isin(list(LATERAL_PORTS.keys())))
                    
                    if ml_result["lm_suspected"] or is_rule_detected:
                        if not ml_result["lm_suspected"]:
                            ml_result["risk_score"] = 4.8
                            ml_result["summary_text"] = "🚨 [보안 정책 경보] 측면이동 의심 포트 접속이 감지되었습니다."
                        st.session_state["ml_result"] = ml_result
                        st.session_state["page"] = "attack"
                    else:
                        st.session_state["ml_result"] = ml_result
                        st.session_state["page"] = "normal"
                    st.rerun()
                except Exception as e:
                    st.error(f"⚠️ 분석 오류: {e}")

# ── 페이지 2: 공격 탐지 ────────────────────────────────────────────
def attack_page():
    api_key = get_api_key()

    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] { background: #0d0d1a !important; }
    [data-testid="stHeader"]           { background: #0d0d1a !important; }
    [data-testid="stSidebar"]          { background: #0a0a14 !important; }
    [data-testid="stSidebarCollapsedControl"] { display: block !important; background-color: rgba(255,255,255,0.15) !important; border-radius: 8px !important; border: 1px solid rgba(255,255,255,0.35) !important; }
    [data-testid="stSidebarCollapsedControl"] span, [data-testid="stSidebarCollapsedControl"] svg { color: #ffffff !important; fill: #ffffff !important; opacity: 1 !important; }
    [data-testid="stSidebarCollapseButton"] { background-color: rgba(255,255,255,0.15) !important; border-radius: 8px !important; border: 1px solid rgba(255,255,255,0.35) !important; }
    [data-testid="stSidebarCollapseButton"] span, [data-testid="stSidebarCollapseButton"] svg { color: #ffffff !important; fill: #ffffff !important; opacity: 1 !important; }
    [data-testid="stExpandSidebarButton"] { background-color: rgba(255,255,255,0.15) !important; border-radius: 8px !important; border: 1px solid rgba(255,255,255,0.35) !important; }
    [data-testid="stExpandSidebarButton"] span, [data-testid="stExpandSidebarButton"] svg { color: #ffffff !important; fill: #ffffff !important; opacity: 1 !important; }
    [data-testid="stBaseButton-headerNoPadding"] { background-color: rgba(255,255,255,0.15) !important; border-radius: 8px !important; }
    [data-testid="stBaseButton-headerNoPadding"] span, [data-testid="stBaseButton-headerNoPadding"] svg { color: #ffffff !important; fill: #ffffff !important; opacity: 1 !important; }
    </style>""", unsafe_allow_html=True)
    df = st.session_state.get("df")
    ml_result = st.session_state.get("ml_result")
    edge_df, risk_scores, lateral_df, high_risk, rule_summary = load_analysis(df)

    ai_summary = ml_result.get("summary_text", "") if ml_result else ""
    combined_summary = f"{ai_summary}\n\n[세부 지표]\n{rule_summary}"
    
    with st.sidebar:
        st.markdown("### 🔍 분석 정보")
        st.error("🚨 측면이동 탐지됨")
        st.markdown(f"**총 패킷:** {len(df):,}건")
        st.markdown(f"**의심 연결:** {len(lateral_df):,}건")
        st.markdown(f"**고위험 IP:** {len(high_risk)}개")

        # ── AI 분석 결과 패널 ────────────────────────
        if ml_result:
            st.markdown("---")
            st.markdown("### 🤖 AI 분석 결과")
            risk_score = ml_result.get("risk_score", 0)
            high_cnt   = ml_result.get("high_risk_count", 0)
            sus_host   = ml_result.get("suspicious_host", "N/A")

            # 위험도 색상 — 0~3 스케일 기준
            if risk_score >= 2.0:
                score_color = "#FF4B4B"
                score_label = "HIGH"
            elif risk_score >= 1.0:
                score_color = "#FFA500"
                score_label = "MEDIUM"
            else:
                score_color = "#00CC88"
                score_label = "LOW"

            st.markdown(f"""
            <div style="background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;padding:12px 14px;margin:6px 0">
                <div style="color:#888;font-size:11px;margin-bottom:4px">평균 위험도</div>
                <div style="color:{score_color};font-size:22px;font-weight:bold">{risk_score} <span style="font-size:12px">{score_label}</span></div>
            </div>
            <div style="background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;padding:12px 14px;margin:6px 0">
                <div style="color:#888;font-size:11px;margin-bottom:4px">AI 위협 탐지</div>
                <div style="color:#FF4B4B;font-size:22px;font-weight:bold">{high_cnt:,}<span style="color:#888;font-size:12px"> 건</span></div>
            </div>
            <div style="background:#1a1a2e;border:1px solid #2a2a4a;border-radius:8px;padding:12px 14px;margin:6px 0">
                <div style="color:#888;font-size:11px;margin-bottom:4px">주요 의심 호스트</div>
                <div style="color:#e0e0ff;font-size:13px;font-family:monospace;word-break:break-all">{sus_host}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        if st.button("🏠 처음으로", use_container_width=True, key="sb_home"):
            go_home()
        st.markdown("---")
        if st.button("🗑️ 대화 초기화", use_container_width=True):
            st.session_state["chat_history"] = []
            st.rerun()
        st.caption("API 키는 .env 파일로 관리됩니다")

    # 헤더
    h1, h2 = st.columns([8, 2])
    with h1:
        st.markdown("## 🚨 Lateral Movement Analyzer")
    with h2:
        st.markdown("<div style='padding-top:14px'>", unsafe_allow_html=True)
        if st.button("🏠 처음으로", use_container_width=True, key="top_home"):
            go_home()
        st.markdown("</div>", unsafe_allow_html=True)

    st.divider()

    # ── 그래프 읽는 법 팝업 (분석 화면 최초 진입 시 1회) ──────────
    if not st.session_state.get("guide_shown"):
        show_graph_guide()
        st.stop()

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.markdown(f'<div class="metric-card"><div class="label">전체 패킷</div><div class="value">{len(df):,}</div></div>', unsafe_allow_html=True)
    with c2: st.markdown(f'<div class="metric-card"><div class="label">측면이동 의심</div><div class="value" style="color:#FF4B4B">{len(lateral_df):,}</div></div>', unsafe_allow_html=True)
    with c3: st.markdown(f'<div class="metric-card"><div class="label">고위험 IP</div><div class="value" style="color:#FFA500">{len(high_risk)}</div></div>', unsafe_allow_html=True)
    with c4: st.markdown(f'<div class="metric-card"><div class="label">관련 IP 수</div><div class="value">{len(risk_scores)}</div></div>', unsafe_allow_html=True)

    graph_col, chat_col = st.columns([5, 5])
    with graph_col:
        title_col, btn_col = st.columns([8, 2])
        with title_col:
            st.markdown('<div class="section-title">네트워크 그래프</div>', unsafe_allow_html=True)
        with btn_col:
            if st.button("🔲 전체화면", use_container_width=True, help="그래프 전용 페이지로 이동"):
                st.session_state["prev_page"] = "attack"
                st.session_state["page"] = "graph_full"
                st.rerun()
        st.components.v1.html(build_graph_html(edge_df, risk_scores), height=620)
    with chat_col:
        st.markdown('<div class="section-title">🤖 데이터 분석 챗봇</div>', unsafe_allow_html=True)
        chat_container = st.container(height=460)
        with chat_container:
            if not st.session_state["chat_history"] and not st.session_state.get("is_thinking"):
                st.markdown("""
                <div style='color:#555;font-size:14px;padding:40px 0;text-align:center;line-height:2.6'>
                    💬 데이터에 대해 질문해보세요<br>
                    <span style='color:#444;font-size:13px'>
                        "가장 위험한 IP가 뭐야?"<br>
                        "공격 흐름을 설명해줘"<br>
                        "포트 4444가 왜 위험해?"<br>
                        "이 공격을 막으려면?"
                    </span>
                </div>""", unsafe_allow_html=True)
            else:
                for msg in st.session_state["chat_history"]:
                    css  = "chat-user" if msg["role"] == "user" else "chat-bot"
                    icon = "🧑" if msg["role"] == "user" else "🤖"
                    st.markdown(f'<div class="{css}">{icon} {msg["content"]}</div>',
                                unsafe_allow_html=True)
                # 로딩 중 말풍선
                if st.session_state.get("is_thinking"):
                    st.markdown("""
                    <div class='chat-bot' style='display:flex;align-items:center;gap:8px'>
                        🤖
                        <span style='display:flex;gap:4px;align-items:center'>
                            <span style='width:7px;height:7px;border-radius:50%;background:#7080ff;
                                animation:bounce 1s infinite 0s'></span>
                            <span style='width:7px;height:7px;border-radius:50%;background:#7080ff;
                                animation:bounce 1s infinite 0.2s'></span>
                            <span style='width:7px;height:7px;border-radius:50%;background:#7080ff;
                                animation:bounce 1s infinite 0.4s'></span>
                        </span>
                        <style>
                        @keyframes bounce {{
                            0%,80%,100%{{transform:translateY(0)}}
                            40%{{transform:translateY(-6px)}}
                        }}
                        </style>
                    </div>""", unsafe_allow_html=True)

        st.markdown("<div style='color:#555;font-size:11px;margin:8px 0 5px'>빠른 질문</div>",
                    unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        with b1:
            if st.button("🔴 고위험 IP 분석", use_container_width=True):
                st.session_state["quick_q"] = "고위험 IP들을 분석해줘"
            if st.button("🛡️ 대응 방안",      use_container_width=True):
                st.session_state["quick_q"] = "이 공격에 대한 대응 방안을 알려줘"
        with b2:
            if st.button("📋 공격 흐름 설명", use_container_width=True):
                st.session_state["quick_q"] = "이 데이터의 공격 흐름을 단계별로 설명해줘"
            if st.button("📊 포트 분석",      use_container_width=True):
                st.session_state["quick_q"] = "사용된 포트들과 의미를 설명해줘"

        user_input = st.chat_input("데이터에 대해 질문하세요...")
        if user_input:
            if not api_key:
                st.warning("⚠️ 현재 모델이 사용 불가 해요!(api-key오류)")
            else:
                # 1. 내 메시지 즉시 저장 + 로딩 상태 ON
                st.session_state["chat_history"].append({"role": "user", "content": user_input})
                st.session_state["is_thinking"] = True
                st.rerun()
        if st.session_state.get("quick_q"):
            user_q = st.session_state["quick_q"]
            st.session_state["quick_q"] = None

            st.session_state["chat_history"].append({
                "role": "user",
                "content": user_q
            })
            st.session_state["is_thinking"] = True
            st.rerun()

        # 로딩 중이면 GPT 호출 후 답변 저장
        if st.session_state.get("is_thinking"):
            reply = chat_with_data(
                st.session_state["chat_history"], combined_summary, api_key
            )
            st.session_state["chat_history"].append({
                "role": "assistant",
                "content": reply
            })
            st.session_state["is_thinking"] = False
            st.rerun()

    tab1, tab2, tab3 = st.tabs(["⚠️ 의심 연결", "📊 IP별 위험도", "📋 전체 데이터"])
    with tab1: st.dataframe(lateral_df.head(200), use_container_width=True)
    with tab2:
        # KeyError 방지를 위해 컬럼명 명시적 생성 및 정렬
        if risk_scores:
            risk_df = pd.DataFrame([{"IP": i, "Score": s} for i, s in risk_scores.items()])
            st.dataframe(risk_df.sort_values("Score", ascending=False), use_container_width=True)
        else:
            st.info("IP별 위험도 데이터가 없습니다.")
    with tab3: st.dataframe(df.head(500), use_container_width=True)

# ── 페이지 4: 그래프 전체화면 ─────────────────────────────────────
def graph_full_page():
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] { background: #0d0d1a !important; }
    [data-testid="stHeader"]           { display: none !important; }
    [data-testid="stSidebarCollapsedControl"] { display: none !important; }
    .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    /* 돌아가기 버튼 고정 */
    div[data-testid="stButton"] > button {
        position: fixed !important;
        top: 12px !important;
        left: 12px !important;
        z-index: 9999 !important;
        background: rgba(112,128,255,0.2) !important;
        border: 1px solid #7080ff !important;
        color: #7080ff !important;
        font-size: 12px !important;
        padding: 4px 12px !important;
    }
    </style>""", unsafe_allow_html=True)

    df = st.session_state.get("df")
    if df is None:
        st.error("데이터가 없습니다.")
        if st.button("🏠 돌아가기"): go_home()
        return

    from analysis import compute_risk, aggregate_edges
    risk_scores = compute_risk(df)
    edge_df     = aggregate_edges(df)

    if st.button("← 돌아가기", key="graph_back"):
        st.session_state["page"] = st.session_state.get("prev_page", "attack")
        st.rerun()

    # 브라우저 화면 높이에서 버튼 영역 뺀 만큼 사용
    st.components.v1.html(
        build_graph_html(edge_df, risk_scores),
        height=10000,  # 매우 크게 설정 → CSS로 실제 높이 제한
        scrolling=False
    )
    # 그래프 iframe을 화면 꽉 차게
    st.markdown("""
    <style>
    iframe { height: calc(100vh - 60px) !important; width: 100% !important; }
    </style>""", unsafe_allow_html=True)


# ── 페이지 3: 정상 ──────────────────────────────────────────────
def normal_page():
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown("<div style='text-align:center; padding:80px 0'><h1>✅</h1><h3>탐지된 위협이 없습니다</h3></div>", unsafe_allow_html=True)
        if st.button("🏠 처음으로", use_container_width=True): go_home()
        if st.button("🔍 그래프 확인", use_container_width=True):
            st.session_state["page"] = "attack"
            st.rerun()

# ── 라우터 ──────────────────────────────────────────────────────
if st.session_state["page"] == "upload": upload_page()
elif st.session_state["page"] == "attack": attack_page()
elif st.session_state["page"] == "normal": normal_page()
elif st.session_state["page"] == "graph_full": graph_full_page()