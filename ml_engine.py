"""
ml_engine.py — 3-stage ML inference engine + XAI for the ZeroDay-Edge RPi5 Node.

Identical classification logic to backend/threat_detection/tasks.py, rewritten as a
standalone singleton with no Django/Celery dependencies.

Stages:
  1. XGBoost + Random Forest consensus (Tree Ensemble)
  2. Deep Autoencoder anomaly detection (Autoencoder Zero-Day)
  3. BiLSTM temporal sequence analysis (BiLSTM Temporal)

XAI:
  - Stage 1: SHAP TreeExplainer on XGBoost
  - Stage 2: Per-feature MSE reconstruction error contribution
  - Stage 3: Absolute scaled-feature magnitude (proxy)
"""

import logging
import os
import threading
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger(__name__)

# On a 4GB Pi 4 (vs 8GB Pi 5), RAM is the binding constraint, not CPU.
# EDGE_LITE_MODE=1 skips the deep-learning stages (Autoencoder/BiLSTM, ~200-400MB
# combined with TF/tflite runtime overhead) and SHAP, running tree-ensemble-only
# classification. Useful when Chromium kiosk is also running on-device.
LITE_MODE = os.environ.get("EDGE_LITE_MODE", "0") == "1"

# Caps joblib/XGBoost/sklearn internal thread pools so they don't oversubscribe
# the Pi 4's 4 cores while Flask, Scapy capture, and (optionally) Chromium are
# also competing for CPU time. Override via EDGE_ML_THREADS.
_ML_THREADS = int(os.environ.get("EDGE_ML_THREADS", "2"))


class _TFLiteModel:
    """
    Thin predict()-compatible wrapper around a tflite Interpreter, so call
    sites written for `keras_model.predict(x, verbose=0)` don't need to change.

    Uses tflite_runtime if available (lightweight, ~1MB, no TensorFlow needed
    on-device) and falls back to tensorflow.lite.Interpreter otherwise.
    Not thread-safe internally, so invocation is serialised with a lock —
    Flask runs threaded, and /api/ingest can race the flow-drain background thread.
    """

    def __init__(self, path: Path):
        try:
            import tflite_runtime.interpreter as tflite
        except ImportError:
            import tensorflow as tf
            tflite = tf.lite

        self._interpreter = tflite.Interpreter(model_path=str(path), num_threads=_ML_THREADS)
        self._interpreter.allocate_tensors()
        self._input_index = self._interpreter.get_input_details()[0]["index"]
        self._output_index = self._interpreter.get_output_details()[0]["index"]
        self._lock = threading.Lock()

    def predict(self, x: np.ndarray, verbose: int = 0) -> np.ndarray:
        x = np.asarray(x, dtype=np.float32)
        with self._lock:
            self._interpreter.set_tensor(self._input_index, x)
            self._interpreter.invoke()
            return self._interpreter.get_tensor(self._output_index)

# Maps the 4 API snake_case keys to their CIC-IDS-2017 Title Case column names.
# Identical to backend/threat_detection/utils.py key_map.
_KEY_MAP = {
    "Flow Duration":  "flow_duration",
    "Tot Fwd Pkts":   "total_fwd_packets",
    "Tot Bwd Pkts":   "total_bwd_packets",
    "Flow Byts/s":    "flow_bytes_per_sec",
}

_AUTO_BLOCK_THRESHOLD = 0.85
_AUTOENCODER_MSE_THRESHOLD = 50.0
_BILSTM_PROB_THRESHOLD = 0.98


class MLEngine:
    """Thread-safe singleton that loads all models once and classifies flows."""

    _instance = None
    _init_lock = threading.Lock()

    def __new__(cls):
        # Double-checked locking — only one instance ever created
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    obj = object.__new__(cls)
                    obj._loaded = False
                    obj._model_dir = Path(__file__).parent / "ml_models"
                    obj._load_lock = threading.Lock()
                    obj.xgb = None
                    obj.rf = None
                    obj.scaler = None
                    obj.feature_columns = None
                    obj.autoencoder = None
                    obj.bilstm = None
                    cls._instance = obj
        return cls._instance

    # ── Model Loading ────────────────────────────────────────────────────

    def load(self):
        """Eagerly load all models. Safe to call multiple times."""
        with self._load_lock:
            if self._loaded:
                return
            self._load_tree_models()
            if LITE_MODE:
                logger.info("MLEngine: EDGE_LITE_MODE=1 — skipping deep models (tree-ensemble only).")
            else:
                self._load_deep_models()
            self._loaded = True
            logger.info("MLEngine: all models loaded.")

    def _load_tree_models(self):
        d = self._model_dir

        try:
            self.xgb = joblib.load(d / "xgboost_model.joblib")
            self._cap_n_jobs(self.xgb)
            logger.info("  ✓ XGBoost loaded")
        except Exception as e:
            logger.error("  ✗ XGBoost: %s", e)

        try:
            self.rf = joblib.load(d / "rf_model.joblib")
            self._cap_n_jobs(self.rf)
            logger.info("  ✓ Random Forest loaded")
        except Exception as e:
            logger.error("  ✗ Random Forest: %s", e)

        try:
            self.feature_columns = joblib.load(d / "feature_columns.joblib")
            logger.info("  ✓ Feature columns loaded (%d features)", len(self.feature_columns))
        except Exception as e:
            logger.error("  ✗ Feature columns: %s", e)

        try:
            self.scaler = joblib.load(d / "scaler.joblib")
            logger.info("  ✓ Scaler loaded")
        except Exception as e:
            logger.error("  ✗ Scaler: %s", e)

    @staticmethod
    def _cap_n_jobs(model):
        """Best-effort: limit a tree model's internal thread pool (see _ML_THREADS)."""
        try:
            if hasattr(model, "set_params"):
                model.set_params(n_jobs=_ML_THREADS)
            elif hasattr(model, "n_jobs"):
                model.n_jobs = _ML_THREADS
        except Exception:
            pass  # not fatal — model just uses its trained-in default

    def _load_deep_models(self):
        """
        Prefer pre-converted .tflite models (run via tflite_runtime — a few MB,
        no TensorFlow install needed on-device). Falls back to the original
        Keras .h5 loading path if .tflite files aren't present, which requires
        full TensorFlow (~400MB+ RAM) — fine on a Pi 5, tight on a 4GB Pi 4.

        Convert once with convert_to_tflite.py (needs TF, run on a dev machine
        or the Pi 5) and copy the resulting .tflite files into ml_models/.
        """
        d = self._model_dir

        tflite_auto = d / "autoencoder.tflite"
        tflite_bilstm = d / "bilstm.tflite"

        if tflite_auto.exists() or tflite_bilstm.exists():
            if tflite_auto.exists():
                try:
                    self.autoencoder = _TFLiteModel(tflite_auto)
                    logger.info("  ✓ Autoencoder loaded (tflite)")
                except Exception as e:
                    logger.warning("  ✗ Autoencoder (tflite): %s", e)
            if tflite_bilstm.exists():
                try:
                    self.bilstm = _TFLiteModel(tflite_bilstm)
                    logger.info("  ✓ BiLSTM loaded (tflite)")
                except Exception as e:
                    logger.warning("  ✗ BiLSTM (tflite): %s", e)
            return

        logger.info("  No .tflite models found — falling back to full TensorFlow (.h5). "
                    "Run convert_to_tflite.py for a lighter footprint on Pi 4.")
        try:
            from tensorflow.keras.models import load_model
            from tensorflow.keras.layers import Dense

            class SafeDense(Dense):
                """Strips unsupported `quantization_config` kwarg from saved models."""
                def __init__(self, *args, **kwargs):
                    kwargs.pop("quantization_config", None)
                    super().__init__(*args, **kwargs)

            objs = {"Dense": SafeDense}

            try:
                self.autoencoder = load_model(str(d / "autoencoder.h5"), custom_objects=objs, compile=False)
                logger.info("  ✓ Autoencoder loaded (.h5)")
            except Exception as e:
                logger.warning("  ✗ Autoencoder: %s", e)

            try:
                self.bilstm = load_model(str(d / "bilstm.h5"), custom_objects=objs, compile=False)
                logger.info("  ✓ BiLSTM loaded (.h5)")
            except Exception as e:
                logger.warning("  ✗ BiLSTM: %s", e)

        except ImportError:
            logger.warning("  Neither tflite models nor TensorFlow available — deep learning models disabled.")

    # ── Feature Preparation ───────────────────────────────────────────────

    def _prepare_features(self, flow_data: dict):
        """
        Aligns flow_data dict to the 78-column CIC-IDS-2017 feature vector.
        Missing columns are zero-padded.

        Returns:
            scaled_vector: np.ndarray shape (1, 78)
            raw_values:    list[float]  — unscaled, for XAI display
        """
        if self.feature_columns is None or self.scaler is None:
            raise ValueError("Feature columns / scaler not loaded.")

        raw_values = []
        for col in self.feature_columns:
            json_key = _KEY_MAP.get(col)
            if json_key and json_key in flow_data:
                raw_values.append(float(flow_data[json_key]))
            else:
                raw_values.append(float(flow_data.get(col, 0.0)))

        fv = np.array([raw_values])           # (1, 78)
        scaled = self.scaler.transform(fv)    # (1, 78)
        return scaled, raw_values

    # ── XAI ──────────────────────────────────────────────────────────────

    def _compute_xai(
        self,
        detected_by: str,
        scaled_fv: np.ndarray,
        raw_values: list[float],
        autoenc_reconstruction: np.ndarray | None = None,
        top_n: int = 8,
    ) -> list[dict]:
        """
        Return top-N feature contributions as a list of dicts:
          {name, raw_value, impact}

        - Stage 1 (Tree Ensemble)    : XGBoost's native TreeSHAP contributions
                                       (pred_contribs=True — exact SHAP values
                                       computed in xgboost's C++ core, no
                                       separate `shap`/numba/llvmlite install
                                       needed, which matters on 32-bit ARM
                                       where those don't have prebuilt wheels)
        - Stage 2 (Autoencoder ZD)   : Per-feature squared reconstruction error
        - Stage 3 (BiLSTM Temporal)  : Absolute scaled-feature magnitude (proxy)
        """
        features = []

        if detected_by == "Tree Ensemble" and self.xgb is not None:
            try:
                import xgboost as xgb
                booster = self.xgb.get_booster() if hasattr(self.xgb, "get_booster") else self.xgb
                dmat = xgb.DMatrix(scaled_fv)
                contribs = booster.predict(dmat, pred_contribs=True)[0]
                vals = contribs[:-1]  # last entry is the bias/base-value term
                top_idx = np.argsort(np.abs(vals))[::-1][:top_n]
                for i in top_idx:
                    features.append({
                        "name": self.feature_columns[i],
                        "raw_value": float(raw_values[i]),
                        "impact": float(vals[i]),
                    })
            except Exception as e:
                logger.warning("XGBoost contribution computation failed: %s", e)

        elif detected_by == "Autoencoder Zero-Day" and autoenc_reconstruction is not None:
            orig = scaled_fv[0]
            recon = autoenc_reconstruction[0]
            per_feat_err = (orig - recon) ** 2
            top_idx = np.argsort(per_feat_err)[::-1][:top_n]
            max_err = per_feat_err.max() or 1.0
            for i in top_idx:
                features.append({
                    "name": self.feature_columns[i],
                    "raw_value": float(raw_values[i]),
                    "impact": float(per_feat_err[i] / max_err),  # normalised 0–1
                })

        elif detected_by == "BiLSTM Temporal":
            mags = np.abs(scaled_fv[0])
            top_idx = np.argsort(mags)[::-1][:top_n]
            max_mag = mags.max() or 1.0
            for i in top_idx:
                features.append({
                    "name": self.feature_columns[i],
                    "raw_value": float(raw_values[i]),
                    "impact": float(mags[i] / max_mag),
                })

        return features

    # ── Classification ─────────────────────────────────────────────────────

    def classify(self, flow_data: dict) -> dict:
        """
        Run the 3-stage cascade on `flow_data` and return a structured result dict.

        Result keys:
          source_ip, dest_ip, threat_class, confidence, detected_by,
          is_blocked, xai_features, timestamp
        """
        src_ip = flow_data.get("source_ip", "0.0.0.0")
        dst_ip = flow_data.get("destination_ip", flow_data.get("dest_ip", "0.0.0.0"))

        result = {
            "source_ip":    src_ip,
            "dest_ip":      dst_ip,
            "threat_class": "Benign",
            "confidence":   0.0,
            "detected_by":  "None",
            "is_blocked":   False,
            "xai_features": [],
            "timestamp":    datetime.utcnow().isoformat(),
        }

        if not self._loaded:
            self.load()

        if self.feature_columns is None or self.scaler is None:
            logger.warning("Models not loaded — returning Benign default.")
            return result

        try:
            scaled_fv, raw_values = self._prepare_features(flow_data)
        except Exception as e:
            logger.error("Feature preparation failed: %s", e)
            return result

        autoenc_recon = None

        # ── Stage 1: Tree Ensemble ──────────────────────────────────────
        if self.xgb is not None and self.rf is not None:
            try:
                xgb_pred = int(self.xgb.predict(scaled_fv)[0])
                rf_pred  = int(self.rf.predict(scaled_fv)[0])
                if xgb_pred == 1 and rf_pred == 1:
                    result["threat_class"] = "Malicious"
                    result["detected_by"]  = "Tree Ensemble"
                    result["confidence"]   = 0.99
            except Exception as e:
                logger.error("Stage 1 (Tree Ensemble) failed: %s", e)

        # ── Stage 2: Autoencoder (Zero-Day) ────────────────────────────
        if result["threat_class"] == "Benign" and self.autoencoder is not None:
            try:
                autoenc_recon = self.autoencoder.predict(scaled_fv, verbose=0)
                mse = float(np.mean(np.power(scaled_fv - autoenc_recon, 2)))

                if mse > _AUTOENCODER_MSE_THRESHOLD:
                    total_fwd    = int(flow_data.get("total_fwd_packets", 0))
                    bytes_per_sec = float(flow_data.get("flow_bytes_per_sec", 0.0))
                    avg_pkt_size  = bytes_per_sec / max(total_fwd, 1)

                    # Heuristic threat-type labelling (same as backend/tasks.py)
                    if total_fwd > 1000 and avg_pkt_size > 1000:
                        result["threat_class"] = "Command Injection / RCE"
                    elif total_fwd > 100 or bytes_per_sec > 2000:
                        result["threat_class"] = "PortScan / DDoS"
                    else:
                        result["threat_class"] = "Malicious"

                    result["detected_by"] = "Autoencoder Zero-Day"
                    result["confidence"]  = min(mse / 100.0, 1.0)
            except Exception as e:
                logger.error("Stage 2 (Autoencoder) failed: %s", e)

        # ── Stage 3: BiLSTM (Temporal) ─────────────────────────────────
        if result["threat_class"] == "Benign" and self.bilstm is not None:
            try:
                bilstm_in  = scaled_fv.reshape(1, 1, scaled_fv.shape[1])
                bilstm_prob = float(self.bilstm.predict(bilstm_in, verbose=0)[0][0])
                if bilstm_prob > _BILSTM_PROB_THRESHOLD:
                    result["threat_class"] = "Malicious"
                    result["detected_by"]  = "BiLSTM Temporal"
                    result["confidence"]   = bilstm_prob
            except Exception as e:
                logger.error("Stage 3 (BiLSTM) failed: %s", e)

        # ── Auto-block ─────────────────────────────────────────────────
        is_threat = result["threat_class"].lower() not in ("benign", "normal")
        if is_threat and result["confidence"] >= _AUTO_BLOCK_THRESHOLD:
            result["is_blocked"] = True

        # ── XAI ────────────────────────────────────────────────────────
        if is_threat and self.feature_columns is not None:
            result["xai_features"] = self._compute_xai(
                detected_by=result["detected_by"],
                scaled_fv=scaled_fv,
                raw_values=raw_values,
                autoenc_reconstruction=autoenc_recon,
            )

        return result
