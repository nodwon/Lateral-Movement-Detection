import pandas as pd
import numpy as np
import xgboost as xgb
import pickle
import os
import traceback

# 모델 경로 — 실행 파일 기준 상대경로
_BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH   = os.path.join(_BASE, 'xgboost_model.pkl')
ENCODER_PATH = os.path.join(_BASE, 'feature_encoders.pkl')

class SecurityAIAgent:
    def __init__(self):
        self.model = None
        self.encoder_dict = None
        self._load_model()

    def _load_model(self):
        try:
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
            with open(ENCODER_PATH, 'rb') as f:
                self.encoder_dict = pickle.load(f)
            print("✅ AI Agent: 4단계 실무형 모델 로드 성공!")
        except Exception as e:
            print(f"⚠️ AI Agent 로드 에러: {e}")

    def _preprocess_data(self, df):
        X = df.copy()

        # [1] 컬럼명 매핑 — 내부 이름 → 모델 피처명
        column_mapping = {
            "SourceAddress": "srcip",
            "DestAddress":   "dstip",
            "DestPort":      "dsport",
            "SrcPort":       "sport",
            "Bytes":         "sbytes",
            "ProtoRaw":      "proto",    # ProtoRaw가 실제 컬럼명
            "Protocol":      "proto",    # 혹시 Protocol로 올 경우 대비
            "Application":   "service",
        }
        # rename 전 충돌 컬럼 제거 (원본에 service가 있으면 Application이 rename될 때 중복 발생)
        if "Application" in X.columns and "service" in X.columns:
            X = X.drop(columns=["service"])  # 원본 service 제거 후 Application → service
        if "ProtoRaw" in X.columns and "proto" in X.columns:
            X = X.drop(columns=["proto"])    # 원본 proto 제거 후 ProtoRaw → proto
        if "Bytes" in X.columns and "sbytes" in X.columns:
            X = X.drop(columns=["sbytes"])   # 원본 sbytes 제거 후 Bytes → sbytes

        X = X.rename(columns=column_mapping)

        # 중복 컬럼 최종 제거
        if X.columns.duplicated().any():
            X = X.loc[:, ~X.columns.duplicated()]

        # [2] 필수 컬럼 기본값 보충
        defaults = {
            "spkts": 2, "dpkts": 1, "dur": 0.5,
            "dbytes": 0, "sttl": 64, "dttl": 64,
            "sloss": 0, "dloss": 0,
            "swin": 0, "dwin": 0, "stcpb": 0, "dtcpb": 0,
            "trans_depth": 0, "res_bdy_len": 0,
            "tcprtt": 0, "synack": 0, "ackdat": 0,
            "is_sm_ips_ports": 0, "ct_state_ttl": 0,
            "ct_flw_http_mthd": 0, "is_ftp_login": 0, "ct_ftp_cmd": 0,
            "ct_srv_src": 1, "ct_srv_dst": 1, "ct_dst_ltm": 1,
            "ct_src_ltm": 1, "ct_src_dport_ltm": 1,
            "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1,
        }
        for col, val in defaults.items():
            if col not in X.columns:
                X[col] = val

        # [3] 프로토콜 소문자 통일
        if "proto" in X.columns:
            X["proto"] = X["proto"].astype(str).str.lower()
        if "service" in X.columns:
            X["service"] = X["service"].astype(str).str.lower()
        if "state" in X.columns:
            X["state"] = X["state"].astype(str).str.upper()

        # [4] 파생 피처 계산 (analysis.py에 없는 경우 보충)
        sbytes = pd.to_numeric(X.get("sbytes", 0), errors="coerce").fillna(0)
        dbytes = pd.to_numeric(X.get("dbytes", 0), errors="coerce").fillna(0)
        spkts  = pd.to_numeric(X.get("spkts",  2), errors="coerce").fillna(2)
        dur    = pd.to_numeric(X.get("dur",   0.5), errors="coerce").fillna(0.5)

        if "avg_sbytes_per_pkt" not in X.columns:
            X["avg_sbytes_per_pkt"] = (sbytes / (spkts + 1)).round(2)
        if "avg_dbytes_per_pkt" not in X.columns:
            X["avg_dbytes_per_pkt"] = (dbytes / (spkts + 1)).round(2)
        if "byte_asymmetry" not in X.columns:
            total = sbytes + dbytes
            X["byte_asymmetry"] = ((sbytes - dbytes) / total.replace(0, 1)).round(4)
        if "conn_rate_per_sec" not in X.columns:
            X["conn_rate_per_sec"] = (spkts / (dur + 0.0001)).round(4)
        if "bytes_per_dur" not in X.columns:
            X["bytes_per_dur"] = (sbytes / (dur + 0.0001)).round(2)
        if "pkts_per_dur" not in X.columns:
            X["pkts_per_dur"] = (spkts / (dur + 0.0001)).round(2)
        if "loss_to_bytes_ratio" not in X.columns:
            X["loss_to_bytes_ratio"] = 0.0

        # [5] 노이즈 컬럼 제거
        drop_cols = ["label", "attack_cat", "risk_level", "predicted_label",
                     "predicted_risk_num", "stime", "ltime", "id",
                     "srcip", "dstip"]  # IP는 피처 아님
        X = X.drop(columns=[c for c in drop_cols if c in X.columns], errors="ignore")

        # [6] LabelEncoder 적용 — encoder_dict가 dict이면 컬럼별로, 아니면 label용으로만
        if self.encoder_dict:
            if isinstance(self.encoder_dict, dict):
                for col, le in self.encoder_dict.items():
                    if col in X.columns and hasattr(le, "classes_"):
                        known = set(le.classes_.astype(str))
                        X[col] = X[col].astype(str).map(
                            lambda v, k=known, c=le.classes_[0]: v if v in k else str(c)
                        )
                        X[col] = le.transform(X[col])
            # encoder_dict가 LabelEncoder 단일 객체인 경우는 라벨 역변환용 → 전처리에서 불필요

        # [7] 모델 피처 순서 맞춤
        try:
            expected = self.model.get_booster().feature_names
        except Exception:
            expected = list(self.model.feature_names_in_) if hasattr(self.model, "feature_names_in_") else []
        if expected:
            for col in expected:
                if col not in X.columns:
                    X[col] = 0
            X = X[expected]

        # 타입 통일
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

        return X

    def analyze(self, df):
        if self.model is None:
            return {"risk_score": 0.0, "lm_suspected": False, "summary_text": "AI 모델 미연결"}

        try:
            X_processed = self._preprocess_data(df)

            # predict_proba 우선, 실패 시 predict로 fallback
            try:
                proba = self.model.predict_proba(X_processed)
                num_classes = proba.shape[1]
                crit_idx = num_classes - 1  # 클래스 2 = 공격

                # 행별 예측 클래스 (argmax)
                pred_classes = np.argmax(proba, axis=1)

                # 공격(2) / 의심(1) / 정상(0) 건수
                critical_count = int(np.sum(pred_classes == crit_idx))
                medium_count   = int(np.sum(pred_classes == crit_idx - 1))

                # 위험 점수 계산
                # - 공격으로 분류된 행들의 평균 확률 사용 (전체 평균은 정상이 희석)
                # - 클래스 [1,2,3] 기준 → 가중 평균으로 0~3 스케일
                weighted_score = float(np.mean(
                    pred_classes * 1.0  # 0=정상, 1=의심, 2=공격
                ))  # 0~2 범위
                # 0~3 스케일로 변환 (클래스 1→1점, 클래스 2→3점)
                if critical_count > 0:
                    # 공격 행들의 평균 확률로 강도 보정
                    crit_rows = proba[pred_classes == crit_idx, crit_idx]
                    crit_avg  = float(np.mean(crit_rows))
                    risk_score = round(1.5 + crit_avg * 1.5, 2)  # 1.5~3.0 범위
                elif medium_count > 0:
                    med_rows  = proba[pred_classes == crit_idx - 1, crit_idx - 1]
                    med_avg   = float(np.mean(med_rows))
                    risk_score = round(med_avg * 1.5, 2)  # 0~1.5 범위
                else:
                    risk_score = round(weighted_score * 0.5, 2)  # 거의 0

                if critical_count > 0:
                    high_risk_count = critical_count
                    is_lm = True
                    status = f"🚨 [Critical] 측면 이동 공격 의심 ({critical_count:,}건)"
                elif medium_count > 0:
                    high_risk_count = medium_count
                    is_lm = False
                    status = f"⚠️ [Medium] 침투 시도 또는 스캔 활동 감지 ({medium_count:,}건)"
                else:
                    high_risk_count = 0
                    is_lm = False
                    status = "✅ 정상적인 네트워크 트래픽입니다."

            except Exception:
                # predict_proba 미지원 → predict로 fallback (클래스 [1,2,3])
                preds = self.model.predict(X_processed)
                if self.encoder_dict and "label" in self.encoder_dict:
                    labels = self.encoder_dict["label"].inverse_transform(preds)
                else:
                    labels = preds
                high_risk_count = int(np.sum(np.array(labels) >= 2))
                avg = float(np.mean(np.array(labels, dtype=float)))
                risk_score = round(avg, 2)
                is_lm = high_risk_count > 0
                status = "🚨 측면이동 의심" if is_lm else "✅ 정상 트래픽"

            # 주요 의심 호스트
            suspicious_host = "N/A"
            if "SourceAddress" in df.columns and high_risk_count > 0:
                try:
                    suspicious_host = df["SourceAddress"].mode()[0]
                except Exception:
                    pass

            return {
                "risk_score":      risk_score,
                "lm_suspected":    is_lm,
                "high_risk_count": high_risk_count,
                "suspicious_host": suspicious_host,
                "summary_text": (
                    f"AI 분석 결과: {status}\n"
                    f"- 위협 탐지: {high_risk_count:,}건 / 전체 {len(df):,}건\n"
                    f"- 위험 점수: {risk_score}\n"
                    f"- 주요 의심 호스트: {suspicious_host}"
                )
            }
        except Exception as e:
            import traceback
            traceback.print_exc()  # 터미널에 상세 에러 출력
            return {
                "risk_score":      0.0,
                "lm_suspected":    False,
                "high_risk_count": 0,
                "suspicious_host": "N/A",
                "summary_text":    f"❌ 분석 에러: {e}"
            }