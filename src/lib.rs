//! Offline verification of IRL proof bundles.
//!
//! This crate is deliberately self-contained: it shares no code with the
//! IRL Engine. The entire verification algorithm is defined by `SPEC.md`
//! and reimplemented here from that document, so it serves both as a
//! working verifier and as a reference implementation of the spec.
//!
//! Verification is pure computation — no network, no database. The only
//! step that requires external tooling is tying each Merkle root to a
//! Bitcoin block, which uses the standard OpenTimestamps client against
//! the receipt embedded in the bundle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// ── Bundle format (SPEC.md §2) ───────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub bundle_version: u32,
    pub generated_at: DateTime<Utc>,
    pub engine_version: String,
    pub period_from: DateTime<Utc>,
    pub period_to: DateTime<Utc>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub spec: serde_json::Value,
    pub traces: Vec<BundleTrace>,
    pub anchors: Vec<BundleAnchor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleTrace {
    pub trace_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub reasoning_hash: String,
    #[serde(default)]
    pub exchange_tx_id: Option<String>,
    #[serde(default)]
    pub final_proof: Option<String>,
    pub verification_status: String,
    pub valid_time: DateTime<Utc>,
    pub txn_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleAnchor {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub leaf_count: i64,
    pub merkle_root: String,
    pub leaves: Vec<String>,
    #[serde(default)]
    pub ots_receipt_base64: Option<String>,
}

// ── Hash constructions (SPEC.md §3) ──────────────────────────────────────────

/// `final_proof = lower-hex SHA-256(reasoning_hash_ascii || "||" || exchange_tx_id_ascii)`
pub fn compute_final_proof(reasoning_hash: &str, exchange_tx_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reasoning_hash.as_bytes());
    hasher.update(b"||");
    hasher.update(exchange_tx_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Binary SHA-256 Merkle root over hex-encoded leaves.
///
/// - Leaves are used in the order supplied (txn_time ascending).
/// - A leaf that decodes to exactly 32 bytes is used as raw bytes;
///   otherwise the UTF-8 bytes of the hex string are SHA-256'd first.
/// - Odd node count at any level duplicates the last node (Bitcoin convention).
/// - Empty input yields `[0u8; 32]`.
pub fn compute_merkle_root(leaves: &[String]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut nodes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|h| match hex::decode(h) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => Sha256::digest(h.as_bytes()).into(),
        })
        .collect();

    while nodes.len() > 1 {
        if nodes.len() % 2 == 1 {
            let last = *nodes.last().expect("nodes is non-empty");
            nodes.push(last);
        }
        nodes = nodes
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect();
    }

    nodes[0]
}

// ── Verification (SPEC.md §4) ────────────────────────────────────────────────

#[derive(Debug, Default, Serialize)]
pub struct VerificationReport {
    pub final_proofs_checked: usize,
    pub final_proof_failures: Vec<String>,
    pub anchors_checked: usize,
    pub anchor_root_failures: Vec<String>,
    pub anchors_with_ots_receipt: usize,
    pub traces_anchored: usize,
    /// Trace falls inside an anchor period but its hash is absent from the
    /// leaf list — evidence of tampering. Hard failure.
    pub inclusion_failures: Vec<String>,
    /// Trace not covered by any anchor in the bundle (e.g. sealed after the
    /// most recent anchor cycle). Warning, not failure.
    pub traces_unanchored: Vec<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.final_proof_failures.is_empty()
            && self.anchor_root_failures.is_empty()
            && self.inclusion_failures.is_empty()
    }
}

/// Run all offline checks against a bundle.
pub fn verify_bundle(bundle: &ProofBundle) -> VerificationReport {
    let mut report = VerificationReport::default();

    // §4.1 — recompute final_proof for every bound trace.
    for trace in &bundle.traces {
        if let (Some(tx_id), Some(claimed)) = (&trace.exchange_tx_id, &trace.final_proof) {
            report.final_proofs_checked += 1;
            let recomputed = compute_final_proof(&trace.reasoning_hash, tx_id);
            if &recomputed != claimed {
                report.final_proof_failures.push(format!(
                    "trace {}: claimed final_proof {} != recomputed {}",
                    trace.trace_id, claimed, recomputed
                ));
            }
        }
    }

    // §4.2 — recompute every anchor's Merkle root from its leaves.
    let mut anchor_leaf_sets: Vec<HashSet<&str>> = Vec::with_capacity(bundle.anchors.len());
    for anchor in &bundle.anchors {
        report.anchors_checked += 1;
        if anchor.ots_receipt_base64.is_some() {
            report.anchors_with_ots_receipt += 1;
        }
        if anchor.leaves.len() as i64 != anchor.leaf_count {
            report.anchor_root_failures.push(format!(
                "anchor {}..{}: leaf_count {} != {} leaves supplied",
                anchor.period_start,
                anchor.period_end,
                anchor.leaf_count,
                anchor.leaves.len()
            ));
        }
        let recomputed = hex::encode(compute_merkle_root(&anchor.leaves));
        if recomputed != anchor.merkle_root {
            report.anchor_root_failures.push(format!(
                "anchor {}..{}: claimed root {} != recomputed {}",
                anchor.period_start, anchor.period_end, anchor.merkle_root, recomputed
            ));
        }
        anchor_leaf_sets.push(anchor.leaves.iter().map(String::as_str).collect());
    }

    // §4.3 — check each trace's inclusion in the anchor covering its txn_time.
    for trace in &bundle.traces {
        let covering = bundle
            .anchors
            .iter()
            .position(|a| trace.txn_time > a.period_start && trace.txn_time <= a.period_end);
        match covering {
            Some(idx) => {
                if anchor_leaf_sets[idx].contains(trace.reasoning_hash.as_str()) {
                    report.traces_anchored += 1;
                } else {
                    report.inclusion_failures.push(format!(
                        "trace {}: txn_time {} falls in anchor {}..{} but reasoning_hash \
                         is absent from its leaf list",
                        trace.trace_id,
                        trace.txn_time,
                        bundle.anchors[idx].period_start,
                        bundle.anchors[idx].period_end
                    ));
                }
            }
            None => report.traces_unanchored.push(trace.trace_id.clone()),
        }
    }

    report
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn hash_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn ts(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, hour, 0, 0).unwrap()
    }

    fn make_trace(hour: u32, tx: Option<&str>) -> BundleTrace {
        let reasoning_hash = hash_hex(format!("snapshot-{hour}").as_bytes());
        let final_proof = tx.map(|t| compute_final_proof(&reasoning_hash, t));
        BundleTrace {
            trace_id: format!("trace-{hour}"),
            agent_id: None,
            reasoning_hash,
            exchange_tx_id: tx.map(String::from),
            final_proof,
            verification_status: if tx.is_some() { "MATCHED" } else { "PENDING" }.into(),
            valid_time: ts(hour) - chrono::Duration::seconds(5),
            txn_time: ts(hour),
        }
    }

    fn make_bundle(traces: Vec<BundleTrace>) -> ProofBundle {
        let leaves: Vec<String> = traces.iter().map(|t| t.reasoning_hash.clone()).collect();
        let root = hex::encode(compute_merkle_root(&leaves));
        ProofBundle {
            bundle_version: 1,
            generated_at: Utc::now(),
            engine_version: "test".into(),
            period_from: ts(0),
            period_to: ts(23),
            agent_id: None,
            spec: serde_json::json!({}),
            traces,
            anchors: vec![BundleAnchor {
                period_start: ts(0),
                period_end: ts(23),
                leaf_count: leaves.len() as i64,
                merkle_root: root,
                leaves,
                ots_receipt_base64: None,
            }],
        }
    }

    #[test]
    fn valid_bundle_passes() {
        let bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
            make_trace(3, None),
        ]);
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.final_proofs_checked, 2);
        assert_eq!(report.traces_anchored, 3);
    }

    #[test]
    fn tampered_final_proof_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.traces[0].final_proof = Some(hash_hex(b"forged"));
        assert!(!verify_bundle(&bundle).passed());
    }

    #[test]
    fn tampered_merkle_root_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.anchors[0].merkle_root = hash_hex(b"forged-root");
        assert!(!verify_bundle(&bundle).passed());
    }

    #[test]
    fn deleted_leaf_breaks_inclusion_and_root() {
        let mut bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
        ]);
        bundle.anchors[0].leaves.remove(0);
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.inclusion_failures.len(), 1);
        assert!(!report.anchor_root_failures.is_empty());
    }

    #[test]
    fn single_leaf_root_is_leaf_itself() {
        let leaf = hash_hex(b"only");
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        assert_eq!(hex::encode(root), leaf);
    }

    #[test]
    fn odd_leaf_count_duplicates_last() {
        let a = hash_hex(b"a");
        let b = hash_hex(b"b");
        let c = hash_hex(b"c");
        let root = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]);

        let pair = |x: &str, y: &str| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(hex::decode(x).unwrap());
            h.update(hex::decode(y).unwrap());
            h.finalize().into()
        };
        let ab = hex::encode(pair(&a, &b));
        let cc = hex::encode(pair(&c, &c));
        let expected = pair(&ab, &cc);
        assert_eq!(root, expected);
    }
}
