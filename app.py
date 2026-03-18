import streamlit as st
from PIL import Image
import numpy as np

# -------------------------------
# 가짜 ML 모델 (추후 교체)
# -------------------------------
def detect_attack(file_bytes):
    """
    실제로는 ML 모델 넣으면 됨
    지금은 랜덤/조건으로 테스트
    """
    # 예시: 파일 크기로 판단 (임시)
    if len(file_bytes) % 2 == 0:
        return True
    return False


# -------------------------------
# 그래프 이미지 생성/불러오기
# -------------------------------
def get_attack_graph():
    """
    실제로는 그래프 알고리즘 결과 이미지 반환
    """
    # 테스트용 이미지 (파일로 바꿔도 됨)
    return Image.open("graph_example.png")


# -------------------------------
# LLM 대응방안 (더미)
# -------------------------------
def get_response_plan():
    """
    실제로는 LLM 호출 (OpenAI 등)
    """
    return """
    🔒 보안 대응 방안:

    1. 의심되는 IP 차단
    2. 트래픽 로그 분석
    3. 해당 세션 강제 종료
    4. IDS/IPS 룰 업데이트
    """


# -------------------------------
# UI 상태 관리
# -------------------------------
if "page" not in st.session_state:
    st.session_state.page = "upload"

# -------------------------------
# 기본 페이지
# -------------------------------
def upload_page():
    st.title("📁 파일 업로드")

    uploaded_file = st.file_uploader(
        "분석할 파일을 업로드하세요",
        type=["pcap", "csv", "log", "txt"]
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()

        # 🔥 공격 탐지
        is_attack = detect_attack(file_bytes)

        if is_attack:
            st.session_state.page = "attack"
        else:
            st.session_state.page = "normal"

        st.session_state.file_bytes = file_bytes
        st.rerun()


# -------------------------------
# 탐지 페이지(측면 공격이 탐지 되었을 때)
# -------------------------------
def attack_page():
    st.title("🚨 공격 탐지됨")

    st.subheader("📊 공격 그래프")

    if st.button("⬅️ 처음으로"):
        st.session_state.page = "upload"
        st.rerun()

    graph_img = get_attack_graph()
    st.image(graph_img, caption="공격 경로 그래프")

    st.subheader("대응 방안")

    response = get_response_plan()
    st.markdown(response)

    if st.button("⬅️ 처음으로"):
        st.session_state.page = "upload"
        st.rerun()


# -------------------------------
# 정상 페이지(측면 공격이 탐지 되지 않았을 때)
# -------------------------------
def normal_page():
    st.title("✅ 분석 결과")

    st.success("탐지가 되지 않았습니다.")

    if st.button("⬅️ 다시 업로드"):
        st.session_state.page = "upload"
        st.rerun()


# -------------------------------
# 화면
# -------------------------------
if st.session_state.page == "upload":
    upload_page()

elif st.session_state.page == "attack":
    attack_page()

elif st.session_state.page == "normal":
    normal_page()