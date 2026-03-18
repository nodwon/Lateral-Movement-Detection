import pandas as pd
import numpy as np
import tempfile, os

# 측면이동 의심 포트
LATERAL_PORTS = {445, 3389, 22, 135, 139, 5985, 5986, 23, 21}

def parse_file(uploaded_file):
    """
    업로드된 파일을 받아서 (features_df, raw_df) 반환
    - features_df : 모델 입력용 피처 1행짜리 DataFrame
    - raw_df      : 원본 데이터 (미리보기용)
    """
    name = uploaded_file.name.lower()

    if name.endswith(".csv"):
        raw_df = pd.read_csv(uploaded_file)
        return _extract_features(raw_df), raw_df

    elif name.endswith(".xlsx"):
        raw_df = pd.read_excel(uploaded_file)
        return _extract_features(raw_df), raw_df

    elif name.endswith(".pcap") or name.endswith(".pcapng"):
        return _parse_pcap(uploaded_file)

    else:
        raise ValueError(f"지원하지 않는 파일 형식: {name}")


def _extract_features(df: pd.DataFrame):
    """
    CSV/Excel 로그에서 피처 추출
    필요 컬럼: SourceAddress, DestAddress, DestPort, Application, EventTime
    """
    # 컬럼명 소문자 통일
    df.columns = [c.strip() for c in df.columns]

    features = {}

    # ① 고유 소스 IP 수
    if 'SourceAddress' in df.columns:
        features['unique_src_ip'] = df['SourceAddress'].nunique()
        # 소스당 평균 목적지 수 (스캐닝 지표)
        features['avg_dest_per_src'] = df.groupby('SourceAddress')['DestAddress'].nunique().mean() \
            if 'DestAddress' in df.columns else 0

    # ② 고유 목적지 IP 수
    if 'DestAddress' in df.columns:
        features['unique_dst_ip'] = df['DestAddress'].nunique()

    # ③ 측면이동 포트 비율
    if 'DestPort' in df.columns:
        df['DestPort'] = pd.to_numeric(df['DestPort'], errors='coerce')
        features['lateral_port_ratio'] = df['DestPort'].isin(LATERAL_PORTS).mean()
        features['unique_dest_port']   = df['DestPort'].nunique()

    # ④ 고유 애플리케이션 수
    if 'Application' in df.columns:
        features['unique_app'] = df['Application'].nunique()

    # ⑤ 시간당 이벤트 수 (EventTime 또는 시간_표시)
    time_col = None
    for c in ['EventTime', '시간_표시', 'Time', 'Timestamp']:
        if c in df.columns:
            time_col = c
            break
    if time_col:
        try:
            df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
            duration_hours = (df[time_col].max() - df[time_col].min()).total_seconds() / 3600
            features['events_per_hour'] = len(df) / max(duration_hours, 0.01)
        except Exception:
            features['events_per_hour'] = 0

    # ⑥ 총 이벤트 수
    features['total_events'] = len(df)

    return pd.DataFrame([features])


def _parse_pcap(uploaded_file):
    """scapy로 PCAP 파싱"""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        raise ImportError("scapy가 설치되지 않았습니다: pip install scapy")

    # 임시파일에 저장 후 파싱
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
        rows = []
        for pkt in packets:
            if IP in pkt:
                row = {
                    'SourceAddress': pkt[IP].src,
                    'DestAddress':   pkt[IP].dst,
                    'DestPort':      pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None),
                    'Application':   'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'OTHER'),
                    'EventTime':     float(pkt.time),
                }
                rows.append(row)
        raw_df = pd.DataFrame(rows)
        return _extract_features(raw_df), raw_df
    finally:
        os.unlink(tmp_path)
