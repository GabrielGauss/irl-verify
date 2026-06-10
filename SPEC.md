# IRL Proof Bundle Specification — v1

**Status: frozen.** Backward-incompatible changes will increment `bundle_version`.

This document fully defines the IRL proof bundle format and its verification
algorithm. A correct implementation of §4 against this document — in any
language — is a complete verifier. No access to the IRL Engine codebase or
to any IRL server is required.

## 1. Purpose

An IRL proof bundle is a self-contained evidence file proving that a set of
autonomous-agent trading decisions:

1. existed in exactly their recorded form at sealing time (**existence**),
2. were never altered afterward (**integrity**),
3. were sealed *before* their exchange executions (**temporal order**),
4. are each cryptographically bound to a specific exchange transaction (**binding**), and
5. are committed to the Bitcoin blockchain via OpenTimestamps, so that not
   even the bundle's producer can rewrite history (**independence**).

A bundle does **not** prove the agent's self-reported reasoning snapshot was
honest at sealing time. It proves nothing was changed after.

## 2. Bundle format

A bundle is a single JSON object, UTF-8 encoded.

| Field | Type | Description |
|---|---|---|
| `bundle_version` | int | This spec: `1` |
| `generated_at` | RFC 3339 | Export time |
| `engine_version` | string | Producing engine version |
| `period_from` | RFC 3339 | Start of covered period (exclusive) |
| `period_to` | RFC 3339 | End of covered period (inclusive) |
| `agent_id` | string \| null | Set when filtered to one agent |
| `spec` | object | Human-readable restatement of §3 (informational) |
| `traces` | array | See §2.1 |
| `anchors` | array | See §2.2 |

### 2.1 Trace

| Field | Type | Description |
|---|---|---|
| `trace_id` | string | Unique trace identifier (UUID) |
| `agent_id` | string \| null | Agent identifier |
| `reasoning_hash` | string | Lower-hex SHA-256 seal of the decision snapshot (§3.1) |
| `exchange_tx_id` | string \| null | Exchange transaction id; null while unbound |
| `final_proof` | string \| null | Binding hash (§3.2); null while unbound |
| `verification_status` | string | `PENDING` \| `MATCHED` \| `DIVERGENT` \| `EXPIRED` \| `SHADOW_HALTED` |
| `valid_time` | RFC 3339 | When the market state the agent acted on was valid |
| `txn_time` | RFC 3339 | When the engine sealed the snapshot |

### 2.2 Anchor

| Field | Type | Description |
|---|---|---|
| `period_start` | RFC 3339 | Anchor period start (exclusive) |
| `period_end` | RFC 3339 | Anchor period end (inclusive) |
| `leaf_count` | int | Number of leaves in the period |
| `merkle_root` | string | Lower-hex 32-byte Merkle root (§3.3) |
| `leaves` | array of string | All `reasoning_hash` values in the period, ordered by `txn_time` ascending |
| `ots_receipt_base64` | string \| null | Raw OpenTimestamps receipt, base64 (§5) |

## 3. Hash constructions

All hashes are SHA-256. All hex is lowercase.

### 3.1 `reasoning_hash`

`reasoning_hash = hex(SHA-256(RFC 8785 canonical JSON of the CognitiveSnapshot))`

The snapshot itself is not included in a bundle (it may contain proprietary
strategy state). The hash alone supports every check in §4. A party holding
the original snapshot can additionally recompute the seal via RFC 8785.

### 3.2 `final_proof`

```
final_proof = hex(SHA-256(ASCII(reasoning_hash) || "||" || ASCII(exchange_tx_id)))
```

The two ASCII strings are concatenated with the two-byte separator `||`
(0x7C 0x7C) between them.

### 3.3 Merkle root

Binary SHA-256 Merkle tree:

1. Each leaf is the 32-byte decoding of a `reasoning_hash` hex string.
   If a leaf string does not decode to exactly 32 bytes, the SHA-256 of its
   UTF-8 bytes is used instead.
2. Leaves are taken in the order supplied (`txn_time` ascending).
3. At each level, if the node count is odd, the last node is duplicated
   (Bitcoin convention).
4. Parent = `SHA-256(left_32_bytes || right_32_bytes)`.
5. An empty leaf list yields a root of 32 zero bytes.

## 4. Verification algorithm

A verifier MUST perform all three checks. The bundle **fails** if any check
in §4.1 or §4.2 fails, or if any inclusion check in §4.3 fails.

### 4.1 Binding

For every trace with non-null `exchange_tx_id` and `final_proof`:
recompute §3.2 and compare with the claimed `final_proof`. Any mismatch is
a failure.

### 4.2 Anchor roots

For every anchor: assert `len(leaves) == leaf_count`, recompute §3.3 over
`leaves`, and compare with the claimed `merkle_root`. Any mismatch is a
failure.

### 4.3 Inclusion

For every trace: find the anchor with
`period_start < txn_time <= period_end`.

- If found and `reasoning_hash` ∈ that anchor's `leaves`: anchored. Pass.
- If found and `reasoning_hash` ∉ `leaves`: **failure** (evidence of
  insertion or deletion after anchoring).
- If no covering anchor exists in the bundle: **warning**, not failure
  (the trace may post-date the most recent anchor cycle).

## 5. Bitcoin anchoring

Each `ots_receipt_base64` decodes to a raw OpenTimestamps receipt for the
32-byte `merkle_root`. Verify with the standard OpenTimestamps client
(https://opentimestamps.org), which checks the commitment path down to a
Bitcoin block header:

```
ots verify anchor-0.ots
```

A receipt may initially be a calendar attestation; it upgrades to a
Bitcoin-complete proof after 1–2 blocks. Receipts can also be re-obtained
by submitting the root to any OTS calendar.

## 6. Threat model summary

| Adversary action | Detected by |
|---|---|
| Edit a sealed field after the fact | §4.1 (binding) and §4.3 (hash absent from leaves) |
| Delete a trace after anchoring | §4.2 (root mismatch when leaf removed) |
| Insert a back-dated trace | §4.2 / §4.3 (anchored root cannot change) + §5 (Bitcoin timestamp) |
| Producer rewrites both traces and anchors | §5 — the Bitcoin-committed root cannot be reproduced for altered data |
| Fabricate snapshot content *before* sealing | **Out of scope** — see §1. Mitigated operationally by pre-registration of model hashes and post-trade divergence detection |
