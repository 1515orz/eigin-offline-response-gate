# Offline tool-response gate experiment

An original, zero-dependency Rust experiment by **1515orz**, prepared with OpenAI Codex assistance for Eigin's local tool-response screening call.

This is a reproducible boundary experiment, **not a trained prompt-injection detector or a production security system**. Natural-language responses always require approval. The proposed free-text classifier has not been trained or validated.

## Reproduce

Requires installed Rust and Python 3.9+. From this repository:

```sh
python3 verify.py
```

No network, external models, or third-party Python packages are needed. The verifier builds/tests the original Rust source and rewrites `results/` with measurements from your machine. Published measurements are from the documented macOS arm64 run; timings may vary.

## Evidence and limits

- 20 Rust boundary tests and 11 CLI checks passed in the recorded run.
- 20 original synthetic English/Danish/mixed cases; the intentionally unsafe keyword baseline gave TP 3, FN 11, FP 3, TN 3.
- Every natural-language fixture abstains. Zero automatic attack releases therefore does not establish detection accuracy or useful benign coverage.
- No trained classifier, external tool execution, independent linguistic review, iPhone measurement, or production integration is included.

See [EXPERIMENT.md](EXPERIMENT.md) for the boundary model, reproducibility details, measurements, and limitations. [results/measurements.json](results/measurements.json) records the original measured hashes and checks; [manifest.json](manifest.json) records this published source snapshot.

## License and attribution

Original experiment code and documentation are MIT licensed; see [LICENSE](LICENSE). No Eigin implementation code, external model weights, private conversations, or account credentials are included. AI assistance is disclosed; this repository makes no claim of prize selection or payment.
