import pandas as pd
from scapy.all import rdpcap, IP # 패킷을 읽기 위한 도구
import os

# 1. 파일 경로 (사용자님이 주신 pcap 경로)
file_path = r"C:\Users\ez\Downloads\1\1.pcap"
def analyze_pcap_data(path):
    print(f"📂 패킷 파일(.pcap)을 읽는 중입니다... 시간이 조금 걸릴 수 있어요.")
    try:
        # [중요] PCAP 파일은 매우 무거우므로, 일단 5000개 패킷만 먼저 읽어봅니다.
        # 잘 돌아가면 숫자를 늘리거나 전체를 읽으세요.
        packets = rdpcap(path, count=500000) 
        
        packet_list = []
        for packet in packets:
            if packet.haslayer(IP): # IP 계층이 있는 패킷만 골라냄
                packet_list.append({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'proto': packet[IP].proto,
                    'length': len(packet),
                    # pcap에는 정답(Label)이 없으므로, 분석용 임시 라벨 생성
                    'label': 0 
                })
        
        df = pd.DataFrame(packet_list)
        
        if df.empty:
            print("❌ 에러: 패킷에서 IP 정보를 추출하지 못했습니다.")
            return None

        print(f"✅ 패킷 {len(df)}개 로드 성공!")

        # 2. 수평 이동(Lateral Movement) 지표 계산
        # 특정 IP가 몇 군데의 목적지로 접속했나?
        fan_out = df.groupby('src_ip')['dst_ip'].nunique().sort_values(ascending=False)
        max_conn = fan_out.max()
        top_ip = fan_out.index[0]

        # 3. 품질 점수 매기기 (PCAP은 라벨이 없으므로 확산도 위주로 평가)
        score = 0
        if max_conn >= 10: score = 100
        elif max_conn >= 5: score = 50

        # 4. 결과 출력
        print("\n" + "="*60)
        print(f"💎 PCAP 데이터 분석 결과: {score}점 / 100점")
        print("="*60)
        print(f"🚩 최다 접속 시도 IP: {top_ip}")
        print(f"🚩 확산 범위: {max_conn}곳의 서버와 연결됨")
        print("-" * 60)

        if score >= 80:
            print("🟢 [판정] Lateral Movement 패턴이 뚜렷합니다! 분석용으로 적합합니다.")
        else:
            print("🟡 [판정] 연결 관계가 단순합니다. 더 복잡한 공격 데이터가 필요할 수 있습니다.")
        
        return df

    except Exception as e:
        print(f"❌ 에러 발생: {e}")
        print("힌트: scapy가 설치되어 있는지, 파일 경로가 정확한지 확인하세요.")
        return None
import pandas as pd

def check_label_ratio(df):
    # 1. 라벨(정답) 컬럼 찾기 (대소문자 구분 없이 'label', 'target', 'class' 검색)
    target_cols = [c for c in df.columns if c.lower() in ['label', 'target', 'class']]
    
    if not target_cols:
        print("❌ 에러: 데이터에서 라벨(정답) 컬럼을 찾을 수 없습니다.")
        return
    
    label_name = target_cols[0]
    print(f"🔍 분석할 라벨 컬럼: [{label_name}]")

    # 2. 개수 및 비율 계산
    counts = df[label_name].value_counts()           # 개수 세기
    ratios = df[label_name].value_counts(normalize=True) * 100  # 비율(%) 계산

    # 3. 결과 출력
    print("-" * 40)
    print(f"{'구분':<15} | {'개수':<10} | {'비율(%)':<10}")
    print("-" * 40)
    
    for label, count in counts.items():
        # 보통 0이나 'benign'은 정상, 그 외는 공격으로 표시함
        status = "정상" if str(label) in ['0', 'benign', 'Normal'] else "공격"
        ratio = ratios[label]
        print(f"{f'{label}({status})':<15} | {count:<10,} | {ratio:>8.2f}%")
    
    print("-" * 40)
    print(f"✅ 총 데이터 개수: {len(df):,}개")

# 실행 예시

if __name__ == "__main__":
    df = analyze_pcap_data(file_path)
    check_label_ratio(df)
