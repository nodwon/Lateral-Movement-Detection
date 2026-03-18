import pandas as pd
from datetime import datetime, timedelta
import random

def generate_sample_data():
    """측면이동 시나리오 샘플 데이터 생성"""
    random.seed(42)
    base_time = datetime(2024, 3, 15, 9, 0, 0)
    records = [
        # 초기 침투
        {"src": "203.0.113.10", "dst": "192.168.1.5",  "port": 443,  "proto": "HTTPS", "packets": 45,  "bytes": 12400, "dt": base_time + timedelta(minutes=2)},
        # 내부 스캔
        {"src": "192.168.1.5",  "dst": "192.168.1.1",  "port": 445,  "proto": "SMB",   "packets": 12,  "bytes": 3200,  "dt": base_time + timedelta(minutes=5)},
        {"src": "192.168.1.5",  "dst": "192.168.1.10", "port": 445,  "proto": "SMB",   "packets": 18,  "bytes": 5100,  "dt": base_time + timedelta(minutes=6)},
        {"src": "192.168.1.5",  "dst": "192.168.1.20", "port": 3389, "proto": "RDP",   "packets": 230, "bytes": 87000, "dt": base_time + timedelta(minutes=8)},
        {"src": "192.168.1.5",  "dst": "192.168.1.30", "port": 22,   "proto": "SSH",   "packets": 95,  "bytes": 34000, "dt": base_time + timedelta(minutes=9)},
        # 2차 횡이동
        {"src": "192.168.1.20", "dst": "192.168.1.100","port": 445,  "proto": "SMB",   "packets": 55,  "bytes": 19200, "dt": base_time + timedelta(minutes=15)},
        {"src": "192.168.1.20", "dst": "192.168.1.200","port": 1433, "proto": "MSSQL", "packets": 120, "bytes": 44000, "dt": base_time + timedelta(minutes=17)},
        {"src": "192.168.1.30", "dst": "192.168.1.100","port": 22,   "proto": "SSH",   "packets": 78,  "bytes": 28000, "dt": base_time + timedelta(minutes=20)},
        # 3차 전파
        {"src": "192.168.1.100","dst": "192.168.1.200","port": 3389, "proto": "RDP",   "packets": 310, "bytes": 112000,"dt": base_time + timedelta(minutes=28)},
        {"src": "192.168.1.100","dst": "192.168.1.50", "port": 445,  "proto": "SMB",   "packets": 42,  "bytes": 15300, "dt": base_time + timedelta(minutes=30)},
        # 정상 트래픽
        {"src": "192.168.1.2",  "dst": "8.8.8.8",      "port": 53,   "proto": "DNS",   "packets": 8,   "bytes": 640,   "dt": base_time + timedelta(minutes=1)},
        {"src": "192.168.1.3",  "dst": "192.168.1.1",  "port": 80,   "proto": "HTTP",  "packets": 22,  "bytes": 7800,  "dt": base_time + timedelta(minutes=3)},
    ]
    df = pd.DataFrame(records)
    df.columns = ["SourceAddress", "DestAddress", "DestPort", "Application", "Packets", "Bytes", "EventTime"]
    return df
