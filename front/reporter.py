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
당신은 20년 차 네트워크 보안 분석 전문가입니다.
아래 네트워크 트래픽 분석 결과를 바탕으로 한국어 보안 리포트를 작성해주세요.

리포트 목적:
- 측면이동(Lateral Movement) 가능성을 빠르게 이해할 수 있게 설명
- 현재 위험 수준과 판단 근거를 명확히 제시
- 실제 관제 담당자가 바로 참고할 수 있는 대응 방안을 제공

반드시 지킬 규칙:
1. 한국어로 작성합니다.
2. 제공된 분석 결과만을 근거로 작성합니다.
3. 데이터에 없는 사실은 단정하지 말고 "추정", "의심", "가능성"으로 표현합니다.
4. 과장된 표현은 피하고, 실무적으로 명확하게 작성합니다.
5. 포트나 트래픽 특징이 중요하면 그 의미를 짧게 설명합니다.

[분석 결과]
- Risk Score: {score:.2f} / 1.00
- 위험 등급: {level}
- 추출된 피처:
{features_str}

[출력 형식]
1. 요약
   - 현재 상황을 2~3줄로 요약
2. 판단 근거
   - 어떤 피처/패턴 때문에 위험하다고 보았는지 핵심 근거 정리
3. 주요 위협 징후
   - 측면이동, 내부 스캐닝, 관리 포트 접근 등 의심 요소 설명
4. 권고 조치사항
   - 우선순위가 높은 대응 방안 3개 이상 제시
5. 추가 확인 항목
   - 추가로 확인할 로그, 계정, 호스트, 포트 등을 제시

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
