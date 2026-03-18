import pandas as pd

def generate_report(score: float, features_df: pd.DataFrame, api_key: str) -> str:
    """
    GPT API로 리포트 생성
    api_key 없으면 룰 기반 리포트 반환
    """
    if not api_key:
        return _fallback_report(score, features_df)

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        features_str = features_df.to_string(index=False)
        level = "HIGH" if score >= 0.7 else ("MEDIUM" if score >= 0.4 else "LOW")

        prompt = f"""
당신은 네트워크 보안 분석 전문가입니다.
아래 네트워크 트래픽 분석 결과를 바탕으로 한국어로 보안 리포트를 작성해주세요.

[분석 결과]
- Risk Score: {score:.2f} / 1.00
- 위험 등급: {level}
- 추출된 피처:
{features_str}

[리포트 형식]
1. 요약 (2~3줄)
2. 주요 위협 징후
3. 권고 조치사항

간결하고 명확하게 작성해주세요.
"""
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
        )
        return response.choices[0].message.content

    except Exception as e:
        return _fallback_report(score, features_df) + f"\n\n> ⚠️ GPT 오류: {str(e)}"


def _fallback_report(score: float, features_df: pd.DataFrame) -> str:
    """GPT 없을 때 기본 리포트"""
    row = features_df.iloc[0]
    level = "HIGH 🔴" if score >= 0.7 else ("MEDIUM 🟡" if score >= 0.4 else "LOW 🟢")

    lateral = row.get('lateral_port_ratio', 0)
    avg_dest = row.get('avg_dest_per_src', 0)
    events   = row.get('events_per_hour', 0)

    lines = [
        f"## 보안 분석 리포트",
        f"",
        f"**위험 등급:** {level} (Score: {score:.2f})",
        f"",
        f"### 분석 요약",
    ]

    if lateral > 0.3:
        lines.append(f"- ⚠️ 측면이동 의심 포트 비율이 **{lateral:.1%}** 로 높습니다 (SMB/RDP/SSH 등)")
    if avg_dest > 5:
        lines.append(f"- ⚠️ 소스 IP당 평균 **{avg_dest:.1f}개** 목적지 접근 — 내부 스캐닝 의심")
    if events > 500:
        lines.append(f"- ⚠️ 시간당 이벤트 **{events:.0f}건** — 비정상적 트래픽 급증")

    lines += [
        f"",
        f"### 권고 조치",
        f"- 의심 소스 IP에 대한 접근 차단 또는 모니터링 강화",
        f"- SMB(445), RDP(3389) 포트 불필요한 외부 노출 차단",
        f"- EDR/SIEM 로그와 교차 분석 권장",
        f"",
        f"> 💡 OpenAI API 키를 Streamlit Secrets에 등록하면 GPT 기반 상세 리포트를 받을 수 있습니다.",
    ]

    return "\n".join(lines)
