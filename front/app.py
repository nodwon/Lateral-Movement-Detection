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

# ── CSS (다원님 오리지널 스타일 복구) ──────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600&display=swap');
* {{ font-family: 'Noto Sans KR', sans-serif; }}
[data-testid="stAppViewContainer"] {{ background: #e8b4a0; }}
[data-testid="stHeader"] {{ background: transparent; }}
[data-testid="stSidebar"] {{ background: #d9a090 !important; }}

/* 사이드바 화살표 시인성 강화 */
[data-testid="stSidebarCollapsedControl"] {{
    background-color: #7080ff !important;
    border-radius: 8px !important;
    padding: 5px !important;
}}
[data-testid="stSidebarCollapsedControl"] svg {{
    fill: white !important;
}}

.logo-fixed {{ position: fixed; bottom: 28px; left: 28px; z-index: 99999; opacity: 0.92; }}
.logo-fixed img {{ width: 100px; filter: drop-shadow(0 2px 6px rgba(0,0,0,0.15)); }}
.main-title {{ font-size: 22px; font-weight: 600; color: #3a2a22; padding: 44px 0 28px; letter-spacing: 3px; text-align: center; }}
.metric-card {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 10px; padding: 14px 18px; text-align: center; }}
.metric-card .label {{ color: #888; font-size: 12px; margin-bottom: 4px; }}
.metric-card .value {{ color: #fff; font-size: 26px; font-weight: bold; }}
.chat-user {{ background: #1e2a4a; border-radius: 12px 12px 2px 12px; padding: 11px 15px; margin: 6px 0; color: #e0e0ff; font-size: 14px; margin-left: 6%; }}
.chat-bot {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 12px 12px 12px 2px; padding: 11px 15px; margin: 6px 0; color: #ccc; font-size: 14px; margin-right: 6%; }}
</style>
{"" if not LOGO_B64 else f'<div class="logo-fixed"><img src="data:image/png;base64,{LOGO_B64}"/></div>'}
""", unsafe_allow_html=True)

if "page" not in st.session_state: st.session_state["page"] = "upload"
if "chat_history" not in st.session_state: st.session_state["chat_history"] = []
if "is_thinking" not in st.session_state: st.session_state["is_thinking"] = False

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
    st.markdown("<style>[data-testid='stAppViewContainer'] { background: #0d0d1a !important; }</style>", unsafe_allow_html=True)
    df = st.session_state.get("df")
    ml_result = st.session_state.get("ml_result")
    edge_df, risk_scores, lateral_df, high_risk, rule_summary = load_analysis(df)
    
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

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.markdown(f'<div class="metric-card"><div class="label">전체 패킷</div><div class="value">{len(df):,}</div></div>', unsafe_allow_html=True)
    with c2: st.markdown(f'<div class="metric-card"><div class="label">측면이동 의심</div><div class="value" style="color:#FF4B4B">{len(lateral_df):,}</div></div>', unsafe_allow_html=True)
    with c3: st.markdown(f'<div class="metric-card"><div class="label">고위험 IP</div><div class="value" style="color:#FFA500">{len(high_risk)}</div></div>', unsafe_allow_html=True)
    with c4: st.markdown(f'<div class="metric-card"><div class="label">관련 IP 수</div><div class="value">{len(risk_scores)}</div></div>', unsafe_allow_html=True)

    graph_col, chat_col = st.columns([5, 5])
    with graph_col:
        st.components.v1.html(build_graph_html(edge_df, risk_scores), height=620)
    with chat_col:
        st.markdown('<div class="section-title">🤖 데이터 분석 챗봇</div>', unsafe_allow_html=True)
        chat_container = st.container(height=460)
        with chat_container:
            for msg in st.session_state["chat_history"]:
                cls = "chat-user" if msg["role"] == "user" else "chat-bot"
                st.markdown(f'<div class="{cls}">{msg["content"]}</div>', unsafe_allow_html=True)
        
        user_input = st.chat_input("질문하세요...")
        if user_input:
            st.session_state["chat_history"].append({"role": "user", "content": user_input})
            st.session_state["is_thinking"] = True
            st.rerun()
        if st.session_state["is_thinking"]:
            reply = chat_with_data(st.session_state["chat_history"], ml_result.get("summary_text", "") + "\n" + rule_summary, get_api_key())
            st.session_state["chat_history"].append({"role": "assistant", "content": reply})
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