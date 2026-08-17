"""
convert_to_tflite.py — One-time conversion of the Keras deep models to TFLite.

Run this ONCE on a machine that has full TensorFlow installed (your dev
machine, or the original Pi 5) — NOT on the Pi 4 itself. It produces
autoencoder.tflite / bilstm.tflite, which ml_engine.py prefers over the .h5
originals: tflite_runtime needs no TensorFlow install and uses a fraction of
the RAM, which matters on a 4GB Pi 4.

Usage:
    pip install tensorflow
    python convert_to_tflite.py

Then copy ml_models/*.tflite to the Pi 4 alongside (or instead of) the .h5
files. The .h5 files are no longer needed on-device once conversion is done.
"""

import sys
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "ml_models"

SOURCES = [
    ("autoencoder.h5", "autoencoder.tflite"),
    ("bilstm.h5", "bilstm.tflite"),
]


def convert(src_name: str, dst_name: str) -> bool:
    import tensorflow as tf
    from tensorflow.keras.layers import Dense

    class SafeDense(Dense):
        def __init__(self, *args, **kwargs):
            kwargs.pop("quantization_config", None)
            super().__init__(*args, **kwargs)

    src = MODEL_DIR / src_name
    dst = MODEL_DIR / dst_name

    if not src.exists():
        print(f"  ⚠ {src_name} not found — skipping")
        return False

    model = tf.keras.models.load_model(str(src), custom_objects={"Dense": SafeDense}, compile=False)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    # Dynamic-range quantization: ~4x smaller, faster inference, lower RAM —
    # no calibration dataset needed and negligible accuracy impact for this model size.
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    dst.write_bytes(tflite_model)
    ratio = src.stat().st_size / max(dst.stat().st_size, 1)
    print(f"  ✓ {src_name} -> {dst_name} ({dst.stat().st_size / 1024:.0f} KB, {ratio:.1f}x smaller)")
    return True


def main():
    if not MODEL_DIR.exists():
        print(f"ml_models/ not found at {MODEL_DIR}")
        sys.exit(1)

    print("Converting deep models to TFLite…")
    any_converted = False
    for src_name, dst_name in SOURCES:
        if convert(src_name, dst_name):
            any_converted = True

    if not any_converted:
        print("Nothing converted — no source .h5 files found in ml_models/.")
        sys.exit(1)

    print("\nDone. Copy the .tflite files to the Pi 4's ml_models/ directory.")
    print("Install tflite-runtime there (see requirements.txt) instead of full tensorflow.")


if __name__ == "__main__":
    main()
