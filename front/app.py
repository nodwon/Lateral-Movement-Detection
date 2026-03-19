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
# 에이전트 초기화 (함수 내 set_page_config 삭제)
@st.cache_resource
def load_agent():
    return SecurityAIAgent()

agent = load_agent()
# ── 환경변수 ──────────────────────────────────────────────────────
load_dotenv()
def get_api_key() -> str:
    if os.getenv("OPENAI_API_KEY"):
        return os.getenv("OPENAI_API_KEY")
    try:
        return st.secrets.get("OPENAI_API_KEY", "")
    except Exception:
        return ""

# ── 로고 base64 인코딩 ────────────────────────────────────────────
def get_logo_b64() -> str:
    logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""


LOGO_B64 = get_logo_b64()

# ── CSS ───────────────────────────────────────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;600&display=swap');
* {{ font-family: 'Noto Sans KR', sans-serif; }}

/* ── 기본 배경 ── */
[data-testid="stAppViewContainer"] {{ background: #e8b4a0; }}
[data-testid="stHeader"]           {{ background: transparent; }}
[data-testid="stSidebar"]          {{ background: #d9a090 !important; }}

/* ── 업로드 화면 — 사이드바 토글 버튼 숨김 ── */
[data-testid="stSidebarCollapsedControl"] {{
    display: none !important;
}}

/* ── 로고 고정 — 왼쪽 하단, 사이드바보다 위 ── */
.logo-fixed {{
    position: fixed;
    bottom: 28px;
    left: 28px;
    z-index: 99999;
    opacity: 0.92;
}}
.logo-fixed img {{
    width: 100px;
    filter: drop-shadow(0 2px 6px rgba(0,0,0,0.15));
}}

/* 타이틀 */
.main-title {{
    font-size: 22px;
    font-weight: 600;
    color: #3a2a22;
    padding: 44px 0 28px;
    letter-spacing: 3px;
    text-align: center;
}}

/* 에러 */
.error-box {{
    background: rgba(180,60,40,0.12);
    border: 1px solid #c0503a;
    border-radius: 8px;
    padding: 14px 20px;
    color: #7a2010;
    font-size: 13px;
    text-align: center;
    margin-top: 14px;
    white-space: pre-line;
}}

/* 교육 패널 */
.edu-panel {{
    background: rgba(255,255,255,0.45);
    border: 1px solid rgba(180,120,100,0.3);
    border-radius: 14px;
    padding: 24px 26px;
    height: 100%;
}}
.edu-section-title {{
    font-size: 13px;
    font-weight: 600;
    color: #5a3a2a;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin: 20px 0 10px;
    padding-bottom: 5px;
    border-bottom: 1px solid rgba(180,120,100,0.25);
}}
.edu-section-title:first-child {{ margin-top: 0; }}
.edu-item {{
    display: flex;
    gap: 10px;
    align-items: flex-start;
    margin: 7px 0;
    font-size: 13px;
    color: #4a3020;
    line-height: 1.6;
}}
.edu-icon {{
    font-size: 15px;
    flex-shrink: 0;
    margin-top: 1px;
}}
.port-badge {{
    display: inline-block;
    background: rgba(200,80,60,0.15);
    border: 1px solid rgba(200,80,60,0.3);
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 12px;
    font-weight: 600;
    color: #8a2010;
    margin: 2px 3px 2px 0;
    font-family: monospace;
}}
.chat-example {{
    background: rgba(80,100,180,0.1);
    border-left: 3px solid rgba(80,100,180,0.4);
    border-radius: 0 6px 6px 0;
    padding: 6px 10px;
    font-size: 12px;
    color: #3a3a6a;
    margin: 5px 0;
    font-style: italic;
}}

/* 분석 화면 */
.metric-card {{
    background: #1a1a2e; border: 1px solid #2a2a4a;
    border-radius: 10px; padding: 14px 18px; text-align: center;
}}
.metric-card .label {{ color: #888; font-size: 12px; margin-bottom: 4px; }}
.metric-card .value {{ color: #fff; font-size: 26px; font-weight: bold; }}
.section-title {{
    color: #7080ff; font-size: 12px; font-weight: bold;
    letter-spacing: 2px; text-transform: uppercase; margin: 14px 0 8px;
}}
.chat-user {{
    background: #1e2a4a; border-radius: 12px 12px 2px 12px;
    padding: 11px 15px; margin: 6px 0;
    color: #e0e0ff; font-size: 14px; margin-left: 6%; line-height: 1.6;
}}
.chat-bot {{
    background: #1a1a2e; border: 1px solid #2a2a4a;
    border-radius: 12px 12px 12px 2px;
    padding: 11px 15px; margin: 6px 0;
    color: #ccc; font-size: 14px; margin-right: 6%; line-height: 1.6;
}}
</style>
{"" if not LOGO_B64 else f'<div class="logo-fixed"><img src="data:image/png;base64,{LOGO_B64}"/></div>'}
""", unsafe_allow_html=True)

# ── 세션 초기화 ───────────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state["page"] = "upload"
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = []

# ── 필수 컬럼 검사 ────────────────────────────────────────────────
# 포맷 A (PCAP 추출) 또는 포맷 B (UNSW-NB15) 둘 중 하나면 통과
REQUIRED_COLS_A = {"ip.src", "ip.dst", "tcp.dstport"}
REQUIRED_COLS_B = {"srcip", "dstip", "dsport"}
MAX_MB = 1000

def validate_file(uploaded_file) -> tuple:
    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > MAX_MB:
        return False, f"⚠️ 파일 크기가 {size_mb:.1f}MB입니다.\n{MAX_MB}MB 이하로 줄여서 올려주세요."
    # 확장자 확인
    file_name = uploaded_file.name.lower()
    
    # 1. PCAP 계열인 경우: CSV 읽기(pd.read_csv)를 건너뜁니다.
    if file_name.endswith(('.pcap', '.pcapng')):
        # 확장자만 확인하고 바로 통과
        return True, ""
    
    try:
        peek = pd.read_csv(uploaded_file, nrows=2, on_bad_lines="skip")
        uploaded_file.seek(0)
        cols = set(peek.columns)
        ok_a = REQUIRED_COLS_A.issubset(cols)
        ok_b = REQUIRED_COLS_B.issubset(cols)
        if not ok_a and not ok_b:
            return False, "⚠️ 필요한 컬럼이 없습니다."
    except Exception as e:
        return False, f"⚠️ 파일을 읽을 수 없습니다: {str(e)}"
    return True, ""
def go_home():
    st.session_state["page"] = "upload"
    st.session_state["df"] = None
    st.session_state["chat_history"] = []
    st.rerun()

def load_analysis(df):
    edge_df     = aggregate_edges(df)
    risk_scores = compute_risk(df)
    lateral_df  = df[df["DestPort"].isin(LATERAL_PORTS)]
    high_risk   = [ip for ip, s in risk_scores.items() if s >= 0.7]
    summary     = build_data_summary(df, risk_scores)
    return edge_df, risk_scores, lateral_df, high_risk, summary


# ══════════════════════════════════════════════════════════════════
# 페이지 1 — 업로드
# ══════════════════════════════════════════════════════════════════
def upload_page():
    st.markdown('<div class="main-title">측면 공격 시각화</div>', unsafe_allow_html=True)

    _, mid_col, _ = st.columns([1, 1.4, 1])

    with mid_col:
        if True:
            uploaded = st.file_uploader(
                "파일 업로드",
                type=["csv", "pcap"],
                label_visibility="collapsed",
            )

            st.markdown("<div style='border-top:1px solid #c8a090;margin:8px 0 16px'></div>",
                        unsafe_allow_html=True)

            st.markdown(
                "<div style='text-align:center;color:#7a5a4a;font-size:13px;margin-bottom:10px'>"
                "파일이 없으신가요?</div>",
                unsafe_allow_html=True
            )
            if st.button("🧪 샘플 데이터로 실행해보기", use_container_width=True):
                with st.spinner("샘플 데이터 로드 중..."):
                    df = generate_sample_data()
                    st.session_state["df"] = df
                    st.session_state["chat_history"] = []
                    st.session_state["page"] = "attack"
                    st.rerun()

            st.markdown("""
            <div style='margin-top:20px;background:rgba(58,42,34,0.08);border:1px solid #c8a090;
                        border-radius:10px;padding:14px 16px;font-size:12px;color:#7a5a4a;'>
                <div style='font-weight:600;margin-bottom:7px;color:#5a3a2a;'>필요 컬럼 (CSV)</div>
                frame.time_relative &nbsp;·&nbsp; ip.src &nbsp;·&nbsp; ip.dst<br>
                ip.proto &nbsp;·&nbsp; frame.len &nbsp;·&nbsp; tcp.dstport
            </div>
            """, unsafe_allow_html=True)
            if uploaded is not None:
                ok, err_msg = validate_file(uploaded)
                if not ok:
                    st.markdown(f'<div class="error-box">{err_msg}</div>', unsafe_allow_html=True)
                else:
                    with st.spinner("📡 AI 에이전트가 침투 흔적을 분석 중..."):
                        try:
                            # 파일 로드 및 세션 저장
                            df = load_pcap(uploaded) if uploaded.name.endswith(('pcap', 'pcapng')) else load_csv(uploaded)
                            st.session_state["df"] = df
                            st.session_state["chat_history"] = []
                            
                            # 🚀 중요: 미리 로드된 전역 'agent'를 사용하여 분석
                            ml_result = agent.analyze(df)
                            st.session_state["ml_result"] = ml_result
                            
                            # AI 판단 결과(lm_suspected)에 따라 페이지 이동
                            st.session_state["page"] = "attack" if ml_result["lm_suspected"] else "normal"
                            st.rerun()
                        except Exception as e:
                            st.error(f"⚠️ 분석 오류 발생: {e}")




# ══════════════════════════════════════════════════════════════════
# 페이지 2 — 공격 탐지 (그래프 + 챗봇)
# ══════════════════════════════════════════════════════════════════
def attack_page():
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] { background: #0d0d1a !important; }
    [data-testid="stHeader"]           { background: #0d0d1a !important; }
    [data-testid="stSidebar"]          { background: #0a0a14 !important; }

    /* 사이드바 여닫기 버튼 (stSidebarCollapseButton) — 밝게 강조 */
    [data-testid="stSidebarCollapseButton"] {
        background-color: rgba(255,255,255,0.15) !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255,255,255,0.35) !important;
    }
    [data-testid="stSidebarCollapseButton"] button {
        background-color: transparent !important;
    }
    [data-testid="stSidebarCollapseButton"] span,
    [data-testid="stSidebarCollapseButton"] svg {
        color: #ffffff !important;
        fill: #ffffff !important;
        opacity: 1 !important;
    }
    /* 사이드바 열기 버튼 — stExpandSidebarButton */
    [data-testid="stExpandSidebarButton"] {
        background-color: rgba(255,255,255,0.15) !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255,255,255,0.35) !important;
    }
    [data-testid="stExpandSidebarButton"] span,
    [data-testid="stExpandSidebarButton"] svg,
    [data-testid="stExpandSidebarButton"] button {
        color: #ffffff !important;
        fill: #ffffff !important;
        opacity: 1 !important;
    }
    /* 혹시 모를 이전 셀렉터도 유지 */
    [data-testid="stSidebarCollapsedControl"] {
        background-color: rgba(255,255,255,0.15) !important;
        border-radius: 8px !important;
        border: 1px solid rgba(255,255,255,0.35) !important;
    }
    [data-testid="stSidebarCollapsedControl"] span,
    [data-testid="stSidebarCollapsedControl"] svg {
        color: #ffffff !important;
        fill: #ffffff !important;
        opacity: 1 !important;
    }
    </style>""", unsafe_allow_html=True)

    df = st.session_state.get("df")
    ml_result = st.session_state.get("ml_result")

    edge_df, risk_scores, lateral_df, high_risk, rule_summary = load_analysis(df)
    api_key = get_api_key()
    ai_summary = ml_result.get("summary_text", "") if ml_result else ""
    combined_summary = f"{ai_summary}\n\n[세부 지표]\n{rule_summary}"

    # 사이드바
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

            # 위험도 색상
            if risk_score >= 0.7:
                score_color = "#FF4B4B"
                score_label = "HIGH"
            elif risk_score >= 0.4:
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

    # 상단 지표
    st.markdown('<div class="section-title">분석 요약</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="label">전체 패킷</div>'
                    f'<div class="value">{len(df):,}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="label">측면이동 의심</div>'
                    f'<div class="value" style="color:#FF4B4B">{len(lateral_df):,}</div></div>',
                    unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="label">고위험 IP</div>'
                    f'<div class="value" style="color:#FFA500">{len(high_risk)}</div></div>',
                    unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="metric-card"><div class="label">관련 IP 수</div>'
                    f'<div class="value">{len(risk_scores)}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # 그래프 + 챗봇
    graph_col, chat_col = st.columns([5, 5])

    with graph_col:
        st.markdown('<div class="section-title">네트워크 그래프 — 노드/엣지 클릭 시 세부정보</div>',
                    unsafe_allow_html=True)
        
        if st.session_state.get("file_type") == "pcap":
            file_bytes = st.session_state.get("file_bytes")

            if file_bytes:
                pcap_file = BytesIO(file_bytes)
                edge_df = pcap_to_edge_df(pcap_file)

        st.components.v1.html(build_graph_html(edge_df, risk_scores), height=620)

    with chat_col:
        
        st.markdown('<div class="section-title">🤖 데이터 분석 챗봇</div>', unsafe_allow_html=True)
    
        # AI 에이전트 요약과 규칙 기반 요약을 합침
        ai_summary = ml_result.get("summary_text", "") if ml_result else "AI 분석 데이터 없음"
        combined_summary = f"{ai_summary}\n\n[상세 지표]\n{rule_summary}"

        if not api_key:
            st.warning("💡 `.env`에 `OPENAI_API_KEY`를 추가하면 챗봇을 사용할 수 있습니다.")

        with st.container(height=460):
            if not st.session_state["chat_history"]:
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
        if "quick_q" in st.session_state:
            user_input = st.session_state.pop("quick_q")

        if user_input:
            if not api_key:
                st.warning("⚠️ .env 파일에 OPENAI_API_KEY를 추가해주세요.")
            else:
                st.session_state["chat_history"].append({"role": "user", "content": user_input})
                with st.spinner("분석 중..."):
                    reply = chat_with_data(
                    st.session_state["chat_history"], combined_summary, api_key
            )                    
                st.session_state["chat_history"].append({"role": "assistant", "content": reply})
                st.rerun()

    # 하단 탭
    st.markdown("<br>", unsafe_allow_html=True)
    tab1, tab2, tab3 = st.tabs(["⚠️ 측면이동 의심 연결", "📊 IP별 위험도", "📋 전체 데이터 (상위 500)"])

    with tab1:
        show = lateral_df.copy()
        show["위험도"] = show["DestPort"].apply(
            lambda p: f"🔴 {LATERAL_PORTS.get(int(p), '?')} (포트 {int(p)})"
            if pd.notna(p) else "-"
        )
        cols = ["SourceAddress", "DestAddress", "위험도", "Bytes"]
        if "EventTime" in show.columns:
            cols = ["EventTime"] + cols
        st.dataframe(show[cols].head(200), use_container_width=True, hide_index=True)

    with tab2:
        risk_df = pd.DataFrame([
            {"IP": ip, "Risk Score": s, "등급": risk_label(s),
             "발신패킷": len(df[df["SourceAddress"] == ip]),
             "수신패킷": len(df[df["DestAddress"] == ip])}
            for ip, s in sorted(risk_scores.items(), key=lambda x: -x[1])
        ])
        st.dataframe(risk_df, use_container_width=True, hide_index=True)

    with tab3:
        show_all = df[["SourceAddress", "DestAddress", "DestPort", "Application", "Bytes"]].head(500)
        st.dataframe(show_all, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════
# 페이지 3 — 정상
# ══════════════════════════════════════════════════════════════════
def normal_page():
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown("""
        <div style='text-align:center; padding:80px 0 40px'>
            <div style='font-size:64px'>✅</div>
            <div style='font-size:22px; color:#3a6a3a; margin-top:20px; font-weight:600;'>
                측면이동 공격이 탐지되지 않았습니다
            </div>
            <div style='font-size:14px; color:#555; margin-top:16px; line-height:1.9'>
                AI 모델이 해당 파일에서 측면이동 의심 트래픽을 감지하지 못했습니다.<br>
                모델 판단이 잘못됐을 수 있으니, 직접 그래프를 확인해보세요.
            </div>
        </div>
        """, unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("🏠 처음으로", use_container_width=True):
                go_home()
        with c2:
            if st.button("🔍 그래도 분석 확인하기", use_container_width=True):
                st.session_state["page"] = "attack"
                st.rerun()


# ── 라우터 ────────────────────────────────────────────────────────
page = st.session_state["page"]
if page == "upload":
    upload_page()
elif page == "attack":
    attack_page()
elif page == "normal":
    normal_page()