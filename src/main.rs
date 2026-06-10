//! irl-verify — offline proof bundle verifier.
//!
//! Usage:
//!   irl-verify <bundle.json> [--dump-ots <dir>] [--json]
//!
//! Exit code 0 = all cryptographic checks passed. Non-zero = failure.

use anyhow::{bail, Context, Result};
use base64::Engine;
use irl_verify::{verify_bundle, ProofBundle, VerificationReport};

struct Args {
    bundle_path: String,
    dump_ots_dir: Option<String>,
    json_output: bool,
}

fn parse_args() -> Result<Args> {
    let argv: Vec<String> = std::env::args().collect();
    let mut bundle_path = None;
    let mut dump_ots_dir = None;
    let mut json_output = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--dump-ots" => {
                i += 1;
                dump_ots_dir = Some(
                    argv.get(i)
                        .context("--dump-ots requires a directory argument")?
                        .clone(),
                );
            }
            "--json" => json_output = true,
            "--help" | "-h" => {
                println!("Usage: irl-verify <bundle.json> [--dump-ots <dir>] [--json]");
                std::process::exit(0);
            }
            other if bundle_path.is_none() => bundle_path = Some(other.to_string()),
            other => bail!("unexpected argument: {other}"),
        }
        i += 1;
    }

    Ok(Args {
        bundle_path: bundle_path.context("missing bundle path (see --help)")?,
        dump_ots_dir,
        json_output,
    })
}

fn dump_ots_receipts(bundle: &ProofBundle, dir: &str) -> Result<usize> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {dir}"))?;
    let mut written = 0;
    for (idx, anchor) in bundle.anchors.iter().enumerate() {
        if let Some(b64) = &anchor.ots_receipt_base64 {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .with_context(|| format!("anchor {idx}: invalid base64 OTS receipt"))?;
            let path = format!("{dir}/anchor-{idx}.ots");
            std::fs::write(&path, bytes).with_context(|| format!("failed to write {path}"))?;
            println!(
                "  wrote {path}  (root: {}  period: {} .. {})",
                anchor.merkle_root, anchor.period_start, anchor.period_end
            );
            written += 1;
        }
    }
    Ok(written)
}

fn print_report(report: &VerificationReport, bundle: &ProofBundle) {
    println!("IRL proof bundle verification");
    println!("  bundle version : {}", bundle.bundle_version);
    println!("  engine version : {}", bundle.engine_version);
    println!(
        "  period         : {} .. {}",
        bundle.period_from, bundle.period_to
    );
    println!("  traces         : {}", bundle.traces.len());
    println!();
    println!(
        "  final_proof    : {} checked, {} failed",
        report.final_proofs_checked,
        report.final_proof_failures.len()
    );
    println!(
        "  merkle roots   : {} recomputed, {} failed",
        report.anchors_checked,
        report.anchor_root_failures.len()
    );
    println!(
        "  inclusion      : {} anchored, {} failed, {} not yet anchored",
        report.traces_anchored,
        report.inclusion_failures.len(),
        report.traces_unanchored.len()
    );
    println!(
        "  OTS receipts   : {}/{} anchors carry a receipt",
        report.anchors_with_ots_receipt, report.anchors_checked
    );

    for failure in report
        .final_proof_failures
        .iter()
        .chain(&report.anchor_root_failures)
        .chain(&report.inclusion_failures)
    {
        println!("  FAIL: {failure}");
    }

    if !report.traces_unanchored.is_empty() {
        println!(
            "  note: {} trace(s) sealed after the most recent anchor cycle; \
             re-export after the next daily anchor to cover them",
            report.traces_unanchored.len()
        );
    }

    println!();
    if report.passed() {
        println!("PASS — all offline cryptographic checks succeeded.");
        if report.anchors_with_ots_receipt > 0 {
            println!("Next: verify Bitcoin anchoring with the OpenTimestamps client:");
            println!("  irl-verify <bundle.json> --dump-ots ./ots");
            println!("  ots verify ./ots/anchor-0.ots");
        }
    } else {
        println!("FAIL — the bundle is inconsistent. See failures above.");
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let raw = std::fs::read_to_string(&args.bundle_path)
        .with_context(|| format!("failed to read {}", args.bundle_path))?;
    let bundle: ProofBundle =
        serde_json::from_str(&raw).context("failed to parse proof bundle JSON")?;

    let report = verify_bundle(&bundle);

    if args.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report, &bundle);
    }

    if let Some(dir) = &args.dump_ots_dir {
        println!();
        let n = dump_ots_receipts(&bundle, dir)?;
        println!("  {n} OTS receipt(s) written to {dir}");
    }

    if !report.passed() {
        std::process::exit(1);
    }
    Ok(())
}
