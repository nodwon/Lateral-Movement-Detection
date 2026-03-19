import sys
sys.path.insert(0, 'front')
import numpy as np
from ai_agent import SecurityAIAgent
from analysis import load_csv

agent = SecurityAIAgent()
with open('front/sample_10k__1_.csv', 'rb') as f:
    df = load_csv(f)

result = agent.analyze(df)
print("risk_score:", result['risk_score'])
print("high_risk_count:", result['high_risk_count'])
print("lm_suspected:", result['lm_suspected'])