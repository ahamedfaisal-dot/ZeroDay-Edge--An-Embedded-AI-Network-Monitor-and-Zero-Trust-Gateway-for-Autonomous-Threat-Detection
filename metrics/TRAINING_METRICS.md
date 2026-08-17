# Training-Time Metrics

These numbers are extracted directly from the saved execution output of
[`scripts/modelTrainingScript.ipynb`](../../scripts/modelTrainingScript.ipynb)
— they are real, not estimated or fabricated.

**Important caveat**: this notebook trained `threat_model_v1.joblib` +
`label_encoder.joblib`, a 15-class XGBoost classifier. That is **not** the
model pipeline `ml_engine.py` actually loads and runs on the Pi — the
deployed system uses the binary `xgboost_model.joblib` + `rf_model.joblib` +
`autoencoder.h5`/`.tflite` + `bilstm.h5`/`.tflite` cascade, trained by
[`scripts/modelTraining1.ipynb`](../../scripts/modelTraining1.ipynb), which
has **no saved evaluation output** anywhere in this repository — it appears
to have been run in Colab without the output cells being saved back.

So: these are real numbers, for a real model, trained on the same source
dataset with a closely related methodology (same feature-cleaning approach,
same 80/20 stratified split) — but not a direct measurement of the exact
models currently running on the Pi. Treat this as evidence the *approach*
achieves strong separability on CIC-IDS-2017, not as a certified accuracy
figure for the deployed cascade. See [`MODEL_ARCHITECTURE.md`](MODEL_ARCHITECTURE.md)
for what's actually measurable about the deployed models without a labeled
test set on hand.

---

## Dataset

- **Source**: CIC-IDS-2017 (`MachineLearningCVE` CSVs — Monday through Friday captures, including Morning/Afternoon DDoS, PortScan, Web Attack, and Infiltration subsets)
- **Sampling**: 15% random sample per source CSV file (`random_state=42`)
- **Master dataset size**: 424,611 rows × 79 columns (before cleaning)
- **Cleaning**: dropped `Flow ID`, `Source/Src IP`, `Destination/Dst IP`, `Timestamp`, `Source/Src Port` (identifier leakage columns), replaced `inf`/`-inf` with `NaN` and dropped those rows
- **Train/test split**: 80/20, stratified by label, `random_state=42`
  - Training: 339,352 rows
  - Testing: 84,839 rows
- **Features**: 78 numeric columns (post-cleaning)

## Class Distribution (15 classes)

| Label                      | Encoded ID |
| -------------------------- | ---------- |
| BENIGN                     | 0          |
| Bot                        | 1          |
| DDoS                       | 2          |
| DoS GoldenEye              | 3          |
| DoS Hulk                   | 4          |
| DoS Slowhttptest           | 5          |
| DoS slowloris              | 6          |
| FTP-Patator                | 7          |
| Heartbleed                 | 8          |
| Infiltration               | 9          |
| PortScan                   | 10         |
| SSH-Patator                | 11         |
| Web Attack - Brute Force   | 12         |
| Web Attack - Sql Injection | 13         |
| Web Attack - XSS           | 14         |

## Model: `threat_model_v1.joblib` (XGBoost, 15-class)

```python
xgb.XGBClassifier(
    tree_method='hist',
    device='cuda',           # trained on a Colab T4 GPU
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    eval_metric='mlogloss',
)
```

## Results (held-out test set, 84,839 flows)

| Metric                         | Value            |
| ------------------------------ | ---------------- |
| **Accuracy**             | **0.9988** |
| **Precision** (weighted) | **0.9988** |
| **Recall** (weighted)    | **0.9988** |
| **F1 Score** (weighted)  | **0.9988** |

Weighted averaging means these figures are dominated by the majority class
(BENIGN, and high-volume attacks like DoS Hulk/PortScan). Per-class
precision/recall/F1 was computed and plotted in the notebook
(`classification_report` → per-class bar chart) but the underlying numeric
table was never printed as text, only rendered as a `matplotlib` image — so
individual class breakdowns (e.g. the true positive rate specifically on
rare classes like `Heartbleed` or `Infiltration`) aren't recoverable as
numbers here. To get those, re-open `scripts/modelTrainingScript.ipynb` in
Jupyter/Colab and re-run cell 13, or add `print(class_metrics)` before the
`.plot()` call.

A single live-inference sanity check was also logged:

```
[INFERENCE LOG] Threat successfully classified as 'BENIGN' with 100.00% confidence
```

(one random test-set sample, correctly classified — illustrative, not a metric.)

## Not evaluated here

- `xgboost_model.joblib` (binary, actually deployed)
- `rf_model.joblib` (binary, actually deployed)
- `autoencoder.h5`/`.tflite` (actually deployed)
- `bilstm.h5`/`.tflite` (actually deployed)

None of these have a saved accuracy/precision/recall/F1 measurement in this
repository. To get real numbers for them, the CIC-IDS-2017 test split would
need to be reconstructed (same `random_state=42`, same 80/20 split, same
feature-cleaning steps as `modelTraining1.ipynb`) and run back through
`ml_engine.py`'s actual `classify()` path — that requires the original
`dataset.csv`, which isn't present in this repository.
