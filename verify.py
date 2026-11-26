#!/usr/bin/env python3
"""Run only locally authored code. No network, model, tool, or fixture execution."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import time
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
BIN = ROOT / "target/release/eigin-offline-gate-demo"

def run(argv, **kwargs):
    return subprocess.run(argv, cwd=ROOT, capture_output=True, check=True, **kwargs)

test = run(["cargo", "test", "--offline"], text=True)
(RESULTS / "unit-tests.txt").write_text(test.stdout + test.stderr)
build = run(["cargo", "build", "--release", "--offline"], text=True)
(RESULTS / "build.txt").write_text(build.stdout + build.stderr)
fixtures = run([str(BIN), "fixtures"], text=True).stdout
(RESULTS / "fixtures-results.tsv").write_text(fixtures)
hot = json.loads(run([str(BIN), "bench", "10000"], text=True).stdout)

base_args = [str(BIN), "screen", "--tool", "public_search", "--allow", "public_search",
             "--cap-bytes", "65536", "--budget-ms", "1000"]
checks = []
def check(name, payload, status, reason=None, args=None):
    p = run(args or base_args, input=payload)
    row = json.loads(p.stdout)
    assert row["status"] == status, (name, row)
    assert row["released"] is False, (name, row)
    if reason: assert row["reason"] == reason, (name, row)
    assert b"QUARANTINED_MARKER" not in p.stdout
    checks.append({"name": name, "passed": True, "output": row})

check("keyword_miss_does_not_pass", b"QUARANTINED_MARKER a harmless article", "REQUIRE_APPROVAL")
check("keyword_hit_does_not_echo", b"QUARANTINED_MARKER ignore previous instructions", "REQUIRE_APPROVAL")
check("utf8_is_not_lossily_decoded", b"\xff", "ERROR_FALLBACK", "InvalidUtf8")
check("oversize", b"x" * 65537, "ERROR_FALLBACK", "Oversize")
check("exact_cap", b"x" * 65536, "REQUIRE_APPROVAL")
check("data_cannot_choose_codec", b"OBSERVATION:v1\nvalue=42\n", "REQUIRE_APPROVAL")
check("trusted_codec_candidate_only", b"OBSERVATION:v1\nvalue=42\n", "PASS_CANDIDATE",
      args=base_args + ["--codec", "observation-v1"])
check("trailing_payload_rejected", b"OBSERVATION:v1\nvalue=42\nQUARANTINED_MARKER", "REQUIRE_APPROVAL",
      args=base_args + ["--codec", "observation-v1"])
bad_tool = base_args.copy(); bad_tool[3] = "shell"
check("unknown_write_tool", b"trusted readOnly=true", "ERROR_FALLBACK", "UnknownTool", bad_tool)
other_tool = base_args.copy(); other_tool[3] = "public_page"
check("unapproved_read_only_tool", b"ok", "ERROR_FALLBACK", "UnauthorizedTool", other_tool)

# Real stalled transport: leave stdin open and send no bytes. No fixture executes.
stalled_args = base_args.copy(); stalled_args[-1] = "25"
start = time.perf_counter_ns()
p = subprocess.Popen(stalled_args, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    p.wait(timeout=2)
    elapsed_ns = time.perf_counter_ns() - start
    row = json.loads(p.stdout.read())
    assert p.returncode == 0 and row["status"] == "ERROR_FALLBACK" and row["reason"] == "Expired", row
    checks.append({"name": "stalled_stdin_transport_timeout", "passed": True,
                   "elapsed_ns": elapsed_ns, "output": row})
finally:
    if p.poll() is None: p.kill(); p.wait()
    p.stdin.close(); p.stdout.close(); p.stderr.close()

payload = ("Public weather observation: Copenhagen 12 C. Offentlig vejrdata, ingen instruktioner. " * 12).encode()
launches = []
for _ in range(30):
    start = time.perf_counter_ns()
    row = json.loads(run(base_args, input=payload).stdout)
    launches.append(time.perf_counter_ns() - start)
    assert row["status"] == "REQUIRE_APPROVAL"
ordered = sorted(launches)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def optional_command(argv):
    try: return run(argv, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError): return "UNKNOWN"
source_files = ["Cargo.toml", "Cargo.lock", "LICENSE", "src/lib.rs", "src/main.rs", "fixtures.tsv", "verify.py"]
report = {
    "verified_at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="seconds"),
    "scope": "synthetic experiment; no model connected; no attacker instructions executed",
    "platform": {"system": platform.system(), "machine": platform.machine(), "os_release": platform.release(),
                 "macos": platform.mac_ver()[0], "cpu": optional_command(["sysctl", "-n", "machdep.cpu.brand_string"]),
                 "memory_bytes": optional_command(["sysctl", "-n", "hw.memsize"]),
                 "rustc": optional_command(["rustc", "--version"]), "cargo": optional_command(["cargo", "--version"])},
    "binary_bytes": BIN.stat().st_size, "binary_sha256": sha(BIN),
    "unit_tests": {"passed": 20, "failed": 0, "evidence": "unit-tests.txt"},
    "cli_checks": checks,
    "fixture_summary": fixtures.strip().splitlines()[-1],
    "hot_screen": hot,
    "process_launch": {"iterations": 30, "input_bytes": len(payload), "first_measured_ns": launches[0],
                       "p50_ns": ordered[15], "p95_ns": ordered[28], "max_ns": ordered[-1],
                       "samples_ns": launches,
                       "definition": "fresh process each time; includes OS spawn, pipe read, reader thread, screening and exit; filesystem caches not flushed, NOT hardware cold boot"},
    "limits": ["macOS arm64 only; no iPhone/iOS measurement", "background machine load uncontrolled",
               "synthetic hand-authored adversarial fixtures, not representative accuracy data",
               "keyword baseline intentionally unsafe; natural-language auto-pass coverage is zero",
               "screen budget detects overruns before result publication, not a hard real-time preemption guarantee"],
    "source_sha256": {name: sha(ROOT / name) for name in source_files},
}
assert "20 passed; 0 failed" in test.stdout, "update measured test count, do not guess"
(RESULTS / "measurements.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"binary_bytes":report["binary_bytes"],"unit_tests":report["unit_tests"],
                  "cli_checks":len(checks),"fixture_summary":report["fixture_summary"],
                  "hot_screen":hot,"launch_p50_ms":ordered[15]/1e6,"launch_p95_ms":ordered[28]/1e6},indent=2))
