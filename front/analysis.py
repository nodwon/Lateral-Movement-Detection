import pandas as pd

# 측면이동 의심 포트
LATERAL_PORTS = {
    445:  "SMB",
    3389: "RDP",
    22:   "SSH",
    135:  "RPC",
    139:  "NetBIOS",
    5985: "WinRM",
    5986: "WinRM(S)",
    1433: "MSSQL",
    23:   "Telnet",
    4444: "Metasploit",  # 실제 데이터에 있음
    21:   "FTP",
}

PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP"}


def load_csv(file) -> pd.DataFrame:
    """
    두 가지 CSV 포맷 모두 지원
    포맷 A (PCAP 추출): frame.time_relative, ip.src, ip.dst, ip.proto, frame.len, tcp.dstport
    포맷 B (UNSW-NB15): srcip, dstip, dsport, sport, proto, sbytes, stime, attack_cat, label
    """
    df = pd.read_csv(file, on_bad_lines="skip")

    # ── 포맷 감지 ──────────────────────────────────────────────────
    cols = set(df.columns)
    is_format_b = "srcip" in cols and "dstip" in cols

    if is_format_b:
        # 포맷 B — UNSW-NB15 계열
        df = df.dropna(subset=["srcip", "dstip"])
        df = df.rename(columns={
            "srcip":  "SourceAddress",
            "dstip":  "DestAddress",
            "dsport": "DestPort",
            "sport":  "SrcPort",
            "sbytes": "Bytes",
            "stime":  "EventTime",
            "proto":  "ProtoRaw",
        })
        # 문자열 프로토콜 → Application
        proto_str_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "arp": "ARP"}
        df["Application"] = df["ProtoRaw"].str.lower().map(proto_str_map).fillna("OTHER")

        # attack_cat 있으면 Application 덮어쓰기
        if "attack_cat" in df.columns:
            mask = df["attack_cat"].notna() & (df["attack_cat"].astype(str).str.strip() != "0") & (df["attack_cat"].astype(str).str.strip() != "")
            df.loc[mask, "Application"] = df.loc[mask, "attack_cat"]

    else:
        # 포맷 A — PCAP 추출 CSV
        df = df.dropna(subset=["ip.src", "ip.dst"])
        df = df.rename(columns={
            "frame.time_relative": "EventTime",
            "ip.src":              "SourceAddress",
            "ip.dst":              "DestAddress",
            "ip.proto":            "Protocol",
            "frame.len":           "Bytes",
            "tcp.srcport":         "SrcPort",
            "tcp.dstport":         "DestPort",
            "tcp.flags":           "Flags",
        })
        df["Protocol"] = pd.to_numeric(df["Protocol"], errors="coerce")
        df["Application"] = df["Protocol"].apply(
            lambda p: PROTO_MAP.get(int(p), "OTHER") if pd.notna(p) else "OTHER"
        )

    # ── 공통 후처리 ────────────────────────────────────────────────
    df["DestPort"] = pd.to_numeric(df["DestPort"], errors="coerce")
    df["SrcPort"]  = pd.to_numeric(df.get("SrcPort", pd.Series(dtype=float)), errors="coerce")
    df["Bytes"]    = pd.to_numeric(df["Bytes"], errors="coerce").fillna(0)

    # 측면이동 포트면 Application 덮어쓰기
    df["Application"] = df.apply(
        lambda r: LATERAL_PORTS.get(int(r["DestPort"]), r["Application"])
                  if pd.notna(r["DestPort"]) else r["Application"], axis=1
    )

    return df


def aggregate_edges(df: pd.DataFrame) -> pd.DataFrame:
    """
    IP쌍 + 포트 단위로 집계 (그래프 엣지용)
    너무 많은 엣지가 생기지 않도록 상위 연결만 추출
    """
    grp = (
        df.groupby(["SourceAddress", "DestAddress", "DestPort", "Application"], dropna=False)
        .agg(Packets=("Bytes", "count"), Bytes=("Bytes", "sum"))
        .reset_index()
    )
    # 측면이동 포트 우선, 나머지는 상위 바이트 기준 제한
    lateral = grp[grp["DestPort"].isin(LATERAL_PORTS)]
    normal  = grp[~grp["DestPort"].isin(LATERAL_PORTS)].nlargest(30, "Bytes")
    result  = pd.concat([lateral, normal]).drop_duplicates()
    result["DestPort"] = result["DestPort"].fillna(0).astype(int)
    return result


def compute_risk(df: pd.DataFrame) -> dict:
    """IP별 위험도 점수 (0.0 ~ 1.0)"""
    risk = {}
    all_ips = set(df["SourceAddress"]) | set(df["DestAddress"])

    for ip in all_ips:
        score = 0.0
        as_src = df[df["SourceAddress"] == ip]

        # ① 측면이동 포트 사용
        lat = as_src[as_src["DestPort"].isin(LATERAL_PORTS)].shape[0]
        score += min(lat * 0.05, 0.45)

        # ② 다수 목적지 접근 (스캐닝)
        n_dst = as_src["DestAddress"].nunique()
        score += min(n_dst * 0.05, 0.3)

        # ③ 트래픽 볼륨
        total_bytes = as_src["Bytes"].sum()
        if total_bytes > 500000:  score += 0.15
        elif total_bytes > 50000: score += 0.07

        risk[ip] = round(min(score, 1.0), 2)
    return risk


def risk_color(score: float) -> str:
    if score >= 0.7: return "#FF4B4B"
    if score >= 0.4: return "#FFA500"
    return "#00CC88"


def risk_label(score: float) -> str:
    if score >= 0.7: return "HIGH"
    if score >= 0.4: return "MEDIUM"
    return "LOW"


def build_data_summary(df: pd.DataFrame, risk_scores: dict) -> str:
    """챗봇에 넘길 데이터 요약"""
    lateral_df = df[df["DestPort"].isin(LATERAL_PORTS)]
    high_risk  = [(ip, s) for ip, s in risk_scores.items() if s >= 0.7]

    lines = [
        "[데이터 요약]",
        f"- 전체 패킷 수: {len(df):,}건",
        f"- 측면이동 의심 패킷: {len(lateral_df):,}건",
        f"- 고위험 IP 수: {len(high_risk)}개",
        f"- 관련 IP 총 수: {len(risk_scores)}개",
        "",
        "[IP별 위험도 (상위 15개)]",
    ]
    for ip, s in sorted(risk_scores.items(), key=lambda x: -x[1])[:15]:
        src_cnt = len(df[df["SourceAddress"] == ip])
        dst_cnt = len(df[df["DestAddress"] == ip])
        lines.append(f"  {ip}: {risk_label(s)} ({s}) | 발신 {src_cnt:,}건 / 수신 {dst_cnt:,}건")

    lines += ["", "[측면이동 의심 연결 (상위 10개)]"]
    edge_df = aggregate_edges(df)
    lat_edges = edge_df[edge_df["DestPort"].isin(LATERAL_PORTS)].head(10)
    for _, row in lat_edges.iterrows():
        proto = LATERAL_PORTS.get(int(row["DestPort"]), "?")
        lines.append(
            f"  {row['SourceAddress']} → {row['DestAddress']} "
            f"| {proto}(포트 {int(row['DestPort'])}) | 패킷 {row['Packets']}건"
        )

    lines += ["", "[포트 분포 (상위 10개)]"]
    port_dist = df["DestPort"].value_counts().head(10)
    for port, cnt in port_dist.items():
        proto = LATERAL_PORTS.get(int(port), "") if pd.notna(port) else ""
        lines.append(f"  포트 {int(port)}{f' ({proto})' if proto else ''}: {cnt:,}건")

    return "\n".join(lines)