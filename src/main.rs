use eigin_offline_gate_demo::*;
use std::io::{self, Read};
use std::time::{Duration, Instant};

fn print_decision(d: Decision) {
    match d {
        Decision::PassCandidate { response_id, value } => println!(
            "{{\"status\":\"PASS_CANDIDATE\",\"response_id\":{response_id},\"value\":{value},\"released\":false}}"
        ),
        Decision::RequireApproval {
            response_id,
            baseline,
        } => println!(
            "{{\"status\":\"REQUIRE_APPROVAL\",\"response_id\":{response_id},\"unsafe_baseline\":\"{baseline:?}\",\"released\":false}}"
        ),
        Decision::ErrorFallback(reason) => println!(
            "{{\"status\":\"ERROR_FALLBACK\",\"reason\":\"{reason:?}\",\"released\":false}}"
        ),
    }
}
fn screen(args: &[String]) -> Result<(), &'static str> {
    let mut tool = None;
    let mut allowed = None;
    let mut cap = None;
    let mut budget = None;
    let mut codec = None;
    if args.len() % 2 != 0 {
        return Err("arguments_must_be_pairs");
    }
    for pair in args.chunks_exact(2) {
        match pair[0].as_str() {
            "--tool" if tool.is_none() => tool = Some(pair[1].as_str()),
            "--allow" if allowed.is_none() => allowed = Some(pair[1].as_str()),
            "--cap-bytes" if cap.is_none() => {
                cap = Some(pair[1].parse::<usize>().map_err(|_| "invalid_cap")?)
            }
            "--budget-ms" if budget.is_none() => {
                budget = Some(pair[1].parse::<u64>().map_err(|_| "invalid_budget")?)
            }
            "--codec" if codec.is_none() => {
                codec = Some(match pair[1].as_str() {
                    "natural" => ResponseCodec::NaturalLanguageOnly,
                    "observation-v1" => ResponseCodec::SyntheticObservationV1,
                    _ => return Err("unknown_codec"),
                });
            }
            _ => return Err("unknown_or_duplicate_argument"),
        }
    }
    let clock = MonotonicClock::default();
    let tool = tool.ok_or("missing_tool")?;
    let allow = ReadOnlyTool::from_trusted_name(allowed.ok_or("missing_allow")?)
        .ok_or("unknown_allowed_tool")?;
    let cap = cap.ok_or("missing_cap")?;
    let budget = budget.ok_or("missing_budget")?;
    let policy = TrustedPolicy::new(&[allow], cap, budget)
        .map_err(|_| "invalid_policy")?
        .with_codec(codec.unwrap_or(ResponseCodec::NaturalLanguageOnly));
    // Bound both stdin bytes and wait time. A blocked reader is terminated when
    // this short-lived CLI process exits; it has no model or tool capabilities.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("bounded-input".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = io::stdin()
                .take((cap + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = tx.send(result);
        })
        .map_err(|_| "reader_thread_error")?;
    let bytes = match rx.recv_timeout(Duration::from_millis(budget)) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return Err("stdin_error"),
        Err(_) => {
            print_decision(Decision::ErrorFallback(Error::Expired));
            return Ok(());
        }
    };
    print_decision(Gate::new(policy).screen(1, tool, &bytes, &clock));
    Ok(())
}
fn fixtures() -> Result<(), &'static str> {
    let mut tp = 0;
    let mut fp = 0;
    let mut tn = 0;
    let mut fn_ = 0;
    let mut total = 0;
    let mut releases = 0;
    println!("id\tlanguage\tlabel\tkind\tunsafe_baseline\tbaseline_error\tgate\treleased");
    for line in include_str!("../fixtures.tsv").lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let f: Vec<_> = line.splitn(5, '\t').collect();
        if f.len() != 5 {
            return Err("invalid_fixture");
        }
        let malicious = match f[2] {
            "malicious" => true,
            "benign" => false,
            _ => return Err("invalid_label"),
        };
        let hit = unsafe_keyword_baseline(f[4]) == BaselineSignal::KeywordHit;
        let error = match (malicious, hit) {
            (true, true) => {
                tp += 1;
                "none"
            }
            (true, false) => {
                fn_ += 1;
                "false_negative"
            }
            (false, true) => {
                fp += 1;
                "false_positive"
            }
            (false, false) => {
                tn += 1;
                "none"
            }
        };
        let clock = MonotonicClock::default();
        let mut gate =
            Gate::new(TrustedPolicy::new(&[ReadOnlyTool::PublicSearch], HARD_CAP, 60_000).unwrap());
        let decision = gate.screen(1, "public_search", f[4].as_bytes(), &clock);
        let released = gate.release_candidate(1, &clock).is_ok();
        releases += usize::from(released);
        total += 1;
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            f[0],
            f[1],
            f[2],
            f[3],
            if hit { "hit" } else { "no_hit" },
            error,
            decision.status(),
            released
        );
        if !matches!(decision, Decision::RequireApproval { .. }) || released {
            return Err("natural_language_gate_violation");
        }
    }
    println!(
        "SUMMARY total={total} baseline_tp={tp} baseline_fn={fn_} baseline_fp={fp} baseline_tn={tn} natural_language_releases={releases}"
    );
    Ok(())
}
fn bench(n: usize) -> Result<(), &'static str> {
    if !(1..=1_000_000).contains(&n) {
        return Err("invalid_bench_count");
    }
    let body =
        "Public weather observation: Copenhagen 12 C. Offentlig vejrdata, ingen instruktioner. "
            .repeat(12);
    let policy = TrustedPolicy::new(&[ReadOnlyTool::PublicSearch], HARD_CAP, 60_000).unwrap();
    let clock = MonotonicClock::default();
    let mut ns = Vec::with_capacity(n);
    for _ in 0..100 {
        let mut g = Gate::new(policy.clone());
        std::hint::black_box(g.screen(1, "public_search", body.as_bytes(), &clock));
    }
    for _ in 0..n {
        let start = Instant::now();
        let mut g = Gate::new(policy.clone());
        let d = g.screen(1, "public_search", body.as_bytes(), &clock);
        if !matches!(d, Decision::RequireApproval { .. }) {
            return Err("bench_did_not_screen");
        }
        std::hint::black_box(d);
        ns.push(start.elapsed().as_nanos());
    }
    ns.sort_unstable();
    println!(
        "{{\"kind\":\"in_process_screen\",\"iterations\":{n},\"warmups\":100,\"input_bytes\":{},\"p50_ns\":{},\"p95_ns\":{},\"max_ns\":{},\"includes_new_gate_and_policy_clone\":true}}",
        body.len(),
        ns[n / 2],
        ns[(n * 95 / 100).min(n - 1)],
        ns[n - 1]
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("screen") => screen(&args[1..]),
        Some("fixtures") if args.len() == 1 => fixtures(),
        Some("bench") if args.len() == 2 => args[1]
            .parse()
            .map_err(|_| "invalid_bench_count")
            .and_then(bench),
        _ => Err(
            "usage_screen_requires_tool_allow_cap_bytes_budget_ms_or_use_fixtures_or_bench_count",
        ),
    };
    if let Err(reason) = result {
        println!("{{\"status\":\"ERROR_FALLBACK\",\"reason\":\"{reason}\",\"released\":false}}");
        std::process::exit(2);
    }
}
