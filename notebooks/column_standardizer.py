import pandas as pd

# 1. 파일 경로 설정 (본인의 환경에 맞게 수정하세요)
input_file = r"C:\Users\ez\Downloads\OneDrive_2026-03-17\UNSW-NB15_1.csv"
output_file = r"C:\Users\ez\Downloads\OneDrive_2026-03-17\UNSW-NB15_with_headers.csv"

# 2. UNSW-NB15 공식 표준 컬럼명 (49개)
col_names = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 
    'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'sjit', 'djit', 'stime', 'ltime', 'sintpkt', 
    'dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 
    'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
]

# 3. 데이터 읽기 및 저장
print(f"🚀 '{input_file}' 파일을 읽는 중...")
# header=None으로 설정하여 데이터의 첫 줄이 컬럼명이 아님을 명시합니다.
df = pd.read_csv(input_file, names=col_names, header=None, low_memory=False)

print(f"💾 '{output_file}' 파일로 저장 중...")
# index=False를 넣어 행 번호가 파일에 포함되지 않게 합니다.
df.to_csv(output_file, index=False, encoding='utf-8')

print("✅ 저장 완료! 이제 헤더가 포함된 새 파일을 사용하세요.")

# 확인을 위해 상위 5행 출력
print(df[['srcip', 'dstip', 'attack_cat', 'label']].head())