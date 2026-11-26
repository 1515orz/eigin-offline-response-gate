# Offline response gate experiment

This is locally authored, MIT-licensed evidence for a proposal, **not a working prompt-injection detector or a production security boundary**. It uses Rust's standard library only. It does not connect an LLM, call external tools, train/download models, or execute fixture instructions.

## Reproduce

From this directory:

```sh
cargo test --offline
cargo build --release --offline
python3 verify.py
```

`verify.py` builds/tests the local code, runs the fixture suite and CLI boundary checks, then writes the actual results to `results/`. It requires an installed Rust toolchain and Python 3.9+; no third-party Python packages or network access are required.

Screen stdin with trusted orchestration parameters (do not construct these flags from tool output):

```sh
printf '%s' 'A public weather report.' | target/release/eigin-offline-gate-demo screen --tool public_search --allow public_search --cap-bytes 65536 --budget-ms 1000
```

This returns `REQUIRE_APPROVAL`, even without a keyword hit. The CLI never approves/releases content. A zero process exit code means the status was emitted, **not that content is safe**. Parse the typed status and preserve the separate release boundary.

The optional `--codec observation-v1` is a trusted-adapter-only demonstration. It accepts only the exact form `OBSERVATION:v1\nvalue=<canonical i64>\n`, then stores an integer. Source field names, free text, extra newlines, overflow, and trailing instructions cannot enter a candidate. The default codec never treats this self-declared format as safe. `PASS_CANDIDATE` is not release; the separate release API renders a fixed `unverified_tool_data` field and the integer. This proves only tiny-grammar canonicalization, not real webpage coverage or truthfulness of the number.

## Boundary model

- `TrustedPolicy` and tool/response IDs come from the host before execution. The closed local catalog includes only `public_search` and `public_page`; a host must audit these actual adapters. An MCP server's self-reported `readOnly` or a claim embedded in content is not authorization.
- **One Gate = one finite agent turn/tool batch.** It is not reusable across turns. At most 64 unique responses are accepted/recorded per gate, including rejected IDs; at most 65,536 bytes per response. Thus retained source content is bounded by 4 MiB plus state/allocation overhead. Releasing/discarding/expiring drops pending bytes; IDs remain spent. Create a fresh policy/gate for a new authorized turn.
- Natural-language outputs always enter quarantine. Only the unsafe baseline's label, never the quarantined text, occurs in `Decision` or CLI output. Unknown tool, unapproved tool, invalid UTF-8, oversized input, elapsed deadlines, invalid policy, closed gate, and resource exhaustion cannot produce a release.
- Approval is a **separate trusted UI event**, outside model-callable APIs. `ApprovalToken` has private fields, is non-Clone/non-serializable, and binds to one gate plus its immutable, non-replaceable pending response. No hash is used for authorization. Consuming it releases exactly that response once; it changes no tool permissions. Approval may still release hostile text: it represents an explicit human exception, not proof that the content is benign.
- `close()` revokes the batch; `discard()` cancels one response; `expire_pending()` removes expired data. Hosts must call them on cancellation/revocation and keep authorization/release methods inaccessible to untrusted models. Rust type privacy is not process isolation or human authentication.

## Time limits

1. The trusted **turn deadline** is absolute on a single monotonic clock established before tool execution. Results arriving after it are rejected. The CLI's `--budget-ms` starts before stdin reception, modelling the remaining turn budget.
2. A separate **per-screen acceptance budget** is 25 ms (`SCREEN_BUDGET_MS`), checked using elapsed time before publishing the decision. Input is byte-bounded; this post-check detects overruns but is not a hard real-time/preemptive scheduler guarantee.
3. A pending response has a separate **5-minute approval TTL**, measured from successful screening. A person can approve after screening's deadline but before this TTL, provided the host has not closed the turn.
4. The CLI reader also enforces a **transport receive timeout**, so stdin that never closes yields `ERROR_FALLBACK` instead of hanging. An embedding host needs its own transport timeout/cancellation.

The host must reuse the same trusted monotonic clock origin throughout a gate's life. Resetting the clock per call breaks deadline semantics. Tests inject clocks for deterministic boundaries; attacker data never supplies a clock.

## What the synthetic fixtures show

`fixtures.tsv` preserves all 20 original hand-authored examples, labelled English, Danish, or mixed language. They include direct instructions, base64/entity/escaped text, split words, homoglyphs, role/policy spoofing, tool escalation, harmless quotation, and ordinary data. Labels are authored for this experiment, not an independent dataset.

The intentionally unsafe English/Danish keyword baseline measured **3 true positives, 11 false negatives, 3 false positives, and 3 true negatives**. Every natural-language example still required approval; **zero** entered the context through the candidate-release API. This is achieved by abstaining on all natural language, not by successful attack detection. It has zero natural-language automatic-pass coverage and unacceptable usability as a complete product.

`results/fixtures-results.tsv` retains every per-case classification/failure. No representative precision/recall, multilingual robustness, or end-to-end LLM attack success claim follows from these cases.

## Measured evidence and limits

The current run's exact timestamp, platform, binary/source SHA-256, all 30 process-launch samples, 10,000 in-process samples' summary, fixture confusion counts, and CLI outcomes are in `results/measurements.json`. Rust unit-test output and build output are preserved separately. The Python runner asserts the actual test count before writing a report.

- Release executable: **369,600 bytes** on the measured macOS arm64 build.
- **20** Rust tests passed; **11** CLI boundary checks passed, including a real stalled stdin timeout.
- 1,032-byte input, 10,000 warmed in-process screens: p50 **833 ns**, p95 **917 ns** in this run. This includes creating a gate and cloning policy; it is not a language model/classifier benchmark.
- 30 fresh-process invocations: p50 **2.101584 ms**, p95 **2.700458 ms**, including process creation, pipes, input thread, screening and exit. Filesystem caches were not flushed: this is process-start latency, not a cold-device or cold-storage measurement.

Background machine load was uncontrolled. These measurements cover one synthetic payload and one Mac. **No iPhone/iOS execution, energy, peak RSS, model performance, browser integration, or real attacker evaluation was measured.** A future compact classifier needs independent data/calibration and an explicit abstention policy; this experiment supplies neither trained weights nor a safe natural-language auto-pass threshold.
