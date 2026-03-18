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
    IP쌍 + 포트 단위로 집계 후 그래프용 엣지 200개, 노드 150개로 제한
    """
    # ① DestPort를 먼저 int로 변환 후 집계
    df2 = df.copy()
    df2["DestPort"] = pd.to_numeric(df2["DestPort"], errors="coerce").fillna(0).astype(int)

    grp = (
        df2.groupby(["SourceAddress", "DestAddress", "DestPort", "Application"], dropna=False)
        .agg(Packets=("Bytes", "count"), Bytes=("Bytes", "sum"))
        .reset_index()
    )

    # ② 측면이동 포트 우선 분리 — 각각 최대 개수 제한
    MAX_LATERAL = 150  # 측면이동 엣지 최대
    MAX_NORMAL  = 50   # 일반 트래픽 엣지 최대

    lateral = grp[grp["DestPort"].isin(LATERAL_PORTS)].nlargest(MAX_LATERAL, "Bytes")
    normal  = grp[~grp["DestPort"].isin(LATERAL_PORTS)].nlargest(MAX_NORMAL, "Bytes")

    # ③ 합치고 상위 200개 제한
    result = pd.concat([lateral, normal]).drop_duplicates().reset_index(drop=True)

    # ④ 노드 150개 제한 — 측면이동 IP 우선 보존
    all_ips = set(result["SourceAddress"]) | set(result["DestAddress"])
    if len(all_ips) > 150:
        lateral_ips = (
            set(result[result["DestPort"].isin(LATERAL_PORTS)]["SourceAddress"]) |
            set(result[result["DestPort"].isin(LATERAL_PORTS)]["DestAddress"])
        )
        keep_ips = set(lateral_ips)
        for _, row in result.nlargest(200, "Bytes").iterrows():
            keep_ips.add(row["SourceAddress"])
            keep_ips.add(row["DestAddress"])
            if len(keep_ips) >= 150:
                break
        result = result[
            result["SourceAddress"].isin(keep_ips) &
            result["DestAddress"].isin(keep_ips)
        ].reset_index(drop=True)

    return result


def compute_risk(df: pd.DataFrame) -> dict:
    """IP별 위험도 점수 (0.0 ~ 1.0) — groupby 벡터 연산으로 최적화"""

    # ① 측면이동 포트 사용 횟수 (소스 IP 기준)
    lat_counts = (
        df[df["DestPort"].isin(LATERAL_PORTS)]
        .groupby("SourceAddress").size()
    )

    # ② 다수 목적지 접근 수 (소스 IP 기준)
    dst_counts = df.groupby("SourceAddress")["DestAddress"].nunique()

    # ③ 트래픽 볼륨 합계 (소스 IP 기준)
    byte_sums = df.groupby("SourceAddress")["Bytes"].sum()

    all_ips = set(df["SourceAddress"]) | set(df["DestAddress"])
    risk = {}
    for ip in all_ips:
        score = 0.0
        score += min(lat_counts.get(ip, 0) * 0.05, 0.45)
        score += min(dst_counts.get(ip, 0) * 0.05, 0.3)
        b = byte_sums.get(ip, 0)
        if b > 500000:  score += 0.15
        elif b > 50000: score += 0.07
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
    src_counts = df.groupby("SourceAddress").size()
    dst_counts2 = df.groupby("DestAddress").size()
    for ip, s in sorted(risk_scores.items(), key=lambda x: -x[1])[:15]:
        src_cnt = int(src_counts.get(ip, 0))
        dst_cnt = int(dst_counts2.get(ip, 0))
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