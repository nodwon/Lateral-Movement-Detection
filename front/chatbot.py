def chat_with_data(messages: list, data_summary: str, api_key: str) -> str:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        system_prompt = f"""당신은 네트워크 보안 분석 전문가 챗봇입니다.
사용자가 업로드한 네트워크 패킷 캡처 데이터를 분석하여
측면이동(Lateral Movement) 공격에 대해 설명하고 질문에 답변합니다.
교육용 인터페이스이므로 쉽고 친절하게 설명해주세요.
한국어로 답변하세요.

현재 업로드된 데이터 분석 결과:
{data_summary}

이 데이터를 기반으로 구체적으로 답변하고, 데이터에 없는 내용은 추측하지 마세요.
답변은 간결하게 핵심만 전달해주세요."""

        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": system_prompt}] + messages,
            max_tokens=500,
        )
        return resp.choices[0].message.content

    except Exception as e:
        return f"⚠️ OpenAI 오류: {str(e)}\n\nAPI 키를 .env 파일에서 확인해주세요."
