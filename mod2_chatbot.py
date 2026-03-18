import os
from typing import Any, Dict

import streamlit as st

st.set_page_config(page_title="test")
st.title("테스트 화면")
st.write("정상 실행 중")


try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# =========================================================
# 1. 기본 설정
# =========================================================

st.set_page_config(
    page_title="Lateral Movement Detection System",
    page_icon="🛡️",
    layout="wide"
)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-5.4"


# =========================================================
# 2. ML 분석 호출 함수
# =========================================================
def run_ml_analysis(uploaded_file) -> Dict[str, Any]:
    """
    업로드된 PCAP 파일을 ML 분석 모듈/서버에 전달하고
    결과를 dict 형태로 반환하는 함수.

    현재는 데모용 더미 데이터 반환.
    나중에 이 부분을 ML 팀 결과 연동 코드로 교체하면 됨.
    """

    filename = uploaded_file.name.lower()

    if "benign" in filename or "normal" in filename:
        return {
            "filename": uploaded_file.name,
            "lm_suspected": False,
            "risk_score": 0.12,
            "suspicious_host": None,
            "unique_dst_count": 1,
            "ports": [80, 443],
            "graph_summary": "특이한 그래프 중심성 변화 없음",
            "reason": "다수 내부 호스트 접근 및 관리 포트 확산 패턴이 확인되지 않음",
            "graph_data": {
                "nodes": [
                    {"id": "10.0.0.10", "label": "10.0.0.10", "risk": "normal"},
                    {"id": "10.0.0.20", "label": "10.0.0.20", "risk": "normal"},
                ],
                "edges": [
                    {"source": "10.0.0.10", "target": "10.0.0.20", "label": "80/443"},
                ]
            }
        }

    return {
        "filename": uploaded_file.name,
        "lm_suspected": True,
        "risk_score": 0.91,
        "suspicious_host": "10.0.0.5",
        "unique_dst_count": 17,
        "ports": [445, 3389, 5985],
        "graph_summary": "PageRank 상위 1%, Betweenness 상위 3%, 다수 내부 호스트 연결",
        "reason": "짧은 시간 내 여러 내부 서버에 관리 포트 중심 접근이 발생하여 lateral movement가 의심됨",
        "graph_data": {
            "nodes": [
                {"id": "10.0.0.5", "label": "10.0.0.5", "risk": "high"},
                {"id": "10.0.0.10", "label": "10.0.0.10", "risk": "normal"},
                {"id": "10.0.0.11", "label": "10.0.0.11", "risk": "normal"},
                {"id": "10.0.0.12", "label": "10.0.0.12", "risk": "normal"},
                {"id": "10.0.0.13", "label": "10.0.0.13", "risk": "normal"},
            ],
            "edges": [
                {"source": "10.0.0.5", "target": "10.0.0.10", "label": "445"},
                {"source": "10.0.0.5", "target": "10.0.0.11", "label": "3389"},
                {"source": "10.0.0.5", "target": "10.0.0.12", "label": "5985"},
                {"source": "10.0.0.5", "target": "10.0.0.13", "label": "445"},
            ]
        }
    }


# =========================================================
# 3. 시스템 프롬프트
# =========================================================
def get_system_prompt() -> str:
    return """
너는 네트워크 보안 분석 챗봇이다.
사용자가 업로드한 PCAP 파일에 대해 ML 모델이 수행한 lateral movement 탐지 결과를 바탕으로 설명하고 대응방안을 제시하는 역할을 맡고 있다.

반드시 아래 원칙을 지켜라.
1. 답변은 한국어로 작성한다.
2. 제공된 분석 결과를 우선 근거로 사용한다.
3. 분석 결과에 없는 내용을 단정적으로 말하지 않는다.
4. 확실하지 않은 내용은 "추정", "의심", "가능성"이라는 표현을 사용한다.
5. 답변은 가능하면 다음 순서를 따른다.
   - 상황 요약
   - 판단 근거
   - 대응 방안
   - 추가 확인 항목
   - 주의 사항
6. 대응 방안은 보안 관제 관점에서 실무적으로 작성한다.
7. 과장하거나 불필요하게 위협적으로 표현하지 않는다.
8. lateral movement가 의심되지 않는 경우에는 과도한 대응을 권하지 않는다.
9. 사용자가 일반 개념을 묻더라도 현재 사건과 연결 가능하면 함께 설명한다.
""".strip()


# =========================================================
# 4. 분석 결과를 LLM용 컨텍스트로 변환
# =========================================================
def build_analysis_context(ml_result: Dict[str, Any]) -> str:
    return f"""
[PCAP 분석 결과]
- 파일명: {ml_result.get("filename")}
- Lateral Movement 의심 여부: {ml_result.get("lm_suspected")}
- 위험 점수: {ml_result.get("risk_score")}
- 의심 호스트(IP): {ml_result.get("suspicious_host")}
- 접속한 내부 목적지 수: {ml_result.get("unique_dst_count")}
- 주요 접근 포트: {ml_result.get("ports")}
- 그래프 요약: {ml_result.get("graph_summary")}
- 탐지 사유: {ml_result.get("reason")}
""".strip()


# =========================================================
# 5. 사용자 프롬프트 생성
# =========================================================
def build_user_prompt(user_question: str, ml_result: Dict[str, Any]) -> str:
    analysis_context = build_analysis_context(ml_result)

    return f"""
{analysis_context}

[사용자 질문]
{user_question}

[답변 요구사항]
- 한국어로 답변하라.
- 반드시 현재 분석 결과를 우선 근거로 설명하라.
- 분석 결과만으로 확정할 수 없는 내용은 추정이라고 표현하라.
- 가능하면 아래 형식을 따르라.
  1. 상황 요약
  2. 판단 근거
  3. 대응 방안
  4. 추가 확인 항목
  5. 주의 사항
""".strip()


# =========================================================
# 6. OpenAI API 호출
# =========================================================
def ask_gpt(user_question: str, ml_result: Dict[str, Any]) -> str:
    if OpenAI is None:
        return "openai 패키지가 설치되어 있지 않습니다. `pip install openai` 후 다시 실행해주세요."

    if not OPENAI_API_KEY:
        return "OPENAI_API_KEY 환경변수가 설정되어 있지 않습니다. 서버 환경변수에 API 키를 설정해주세요."

    client = OpenAI(api_key=OPENAI_API_KEY)

    system_prompt = get_system_prompt()
    user_prompt = build_user_prompt(user_question, ml_result)

    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.output_text
    except Exception as e:
        return f"GPT API 호출 중 오류가 발생했습니다: {e}"


# =========================================================
# 7. 챗봇 응답 래퍼
# =========================================================
def chatbot_answer(user_question: str, ml_result: Dict[str, Any]) -> str:
    return ask_gpt(user_question, ml_result)


# =========================================================
# 8. LM 의심 여부 판단
# =========================================================
def is_lm_suspected(ml_result: Dict[str, Any]) -> bool:
    return bool(ml_result.get("lm_suspected", False))


# =========================================================
# 9. 결과 요약 출력
# =========================================================
def render_result_summary(ml_result: Dict[str, Any]) -> None:
    st.subheader("분석 결과 요약")

    col1, col2, col3 = st.columns(3)
    col1.metric("LM 의심 여부", "의심" if ml_result.get("lm_suspected") else "정상")
    col2.metric("위험 점수", str(ml_result.get("risk_score")))
    col3.metric("의심 호스트", str(ml_result.get("suspicious_host")))

    st.write(f"**파일명**: {ml_result.get('filename')}")
    st.write(f"**주요 포트**: {ml_result.get('ports')}")
    st.write(f"**그래프 요약**: {ml_result.get('graph_summary')}")
    st.write(f"**탐지 사유**: {ml_result.get('reason')}")

    with st.expander("원본 분석 결과(JSON) 보기"):
        st.json(ml_result)


# =========================================================
# 10. 그래프 출력
# =========================================================
def render_graph(graph_data: Dict[str, Any]) -> None:
    st.subheader("그래프 시각화")

    if not graph_data:
        st.warning("그래프 데이터가 없습니다.")
        return

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    st.write("### 노드 목록")
    for node in nodes:
        risk = node.get("risk", "normal")
        if risk == "high":
            st.markdown(f"- 🔴 **{node.get('label')}** (고위험)")
        else:
            st.markdown(f"- 🟢 {node.get('label')}")

    st.write("### 연결 관계")
    for edge in edges:
        st.markdown(
            f"- `{edge.get('source')}` → `{edge.get('target')}` "
            f"(port/proto: {edge.get('label')})"
        )


# =========================================================
# 11. 추천 질문 버튼
# =========================================================
def render_suggested_questions() -> None:
    st.write("### 추천 질문")
    qcols = st.columns(5)

    questions = [
        "왜 이 PCAP이 Lateral Movement 의심으로 판단되었나요?",
        "가장 위험한 호스트(IP)는 무엇이고, 왜 위험한가요?",
        "지금 가장 먼저 해야 할 대응 조치는 무엇인가요?",
        "추가로 어떤 로그나 보안 장비 기록을 확인해야 하나요?",
        "이 공격이 실제 내부 확산 공격일 가능성은 어느 정도인가요?",
    ]

    for idx, q in enumerate(questions):
        with qcols[idx]:
            if st.button(f"질문 {idx + 1}", use_container_width=True):
                st.session_state.pending_question = q


# =========================================================
# 12. 챗봇 화면
# =========================================================
def render_chatbot(ml_result: Dict[str, Any]) -> None:
    st.subheader("보안 분석 챗봇")

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    render_suggested_questions()

    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    default_question = st.session_state.pop("pending_question", None)
    if default_question:
        user_input = default_question
    else:
        user_input = st.chat_input("질문을 입력하세요")

    if user_input:
        st.session_state.chat_messages.append({
            "role": "user",
            "content": user_input
        })

        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):
            with st.spinner("GPT가 답변을 생성하는 중입니다..."):
                answer = chatbot_answer(user_input, ml_result)
                st.markdown(answer)

        st.session_state.chat_messages.append({
            "role": "assistant",
            "content": answer
        })


# =========================================================
# 13. 세션 초기화
# =========================================================
def reset_session_state() -> None:
    keys_to_clear = ["ml_result", "chat_messages", "pending_question"]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]


# =========================================================
# 14. 메인 앱
# =========================================================
def main() -> None:
    st.title("🛡️ Lateral Movement Detection System")
    st.caption("PCAP 업로드 → ML 분석 → LM 의심 시 그래프 및 챗봇 제공")

    with st.sidebar:
        st.header("설정")
        st.write(f"OpenAI 모델: `{OPENAI_MODEL}`")
        st.write("API 키는 환경변수 `OPENAI_API_KEY`로 설정해야 합니다.")
        if st.button("세션 초기화"):
            reset_session_state()
            st.rerun()

    uploaded_file = st.file_uploader(
        "PCAP 파일을 업로드하세요",
        type=["pcap", "pcapng"]
    )

    if uploaded_file is not None:
        st.write(f"업로드된 파일: **{uploaded_file.name}**")

        if st.button("분석 시작", type="primary"):
            with st.spinner("ML 분석 중입니다..."):
                ml_result = run_ml_analysis(uploaded_file)
                st.session_state.ml_result = ml_result
                st.session_state.chat_messages = []

    if "ml_result" in st.session_state:
        ml_result = st.session_state.ml_result
        render_result_summary(ml_result)

        if is_lm_suspected(ml_result):
            st.success("Lateral Movement 의심이 탐지되었습니다.")
            st.divider()
            render_graph(ml_result.get("graph_data", {}))
            st.divider()
            render_chatbot(ml_result)
        else:
            st.info("Lateral Movement가 의심되지 않습니다.")
            st.write("현재 분석 결과 기준으로 추가 챗봇 창은 열리지 않습니다.")


if __name__ == "__main__":
    main()