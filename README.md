# irl-verify

**Offline verifier for IRL (Immutable Reasoning Log) proof bundles.**
No network. No database. No trust in the operator.

[IRL](https://macropulse.live/irl) is a pre-execution compliance gateway for
autonomous trading agents: it cryptographically seals every AI decision
before the order reaches the exchange, binds it to the resulting exchange
transaction, and commits daily Merkle roots to the Bitcoin blockchain via
[OpenTimestamps](https://opentimestamps.org).

This tool lets **anyone** — an auditor, an allocator, a regulator, a
counterparty — take a proof bundle exported from an IRL deployment and
verify the entire chain on their own machine:

```
$ irl-verify may-2026.bundle.json

IRL proof bundle verification
  final_proof    : 4212 checked, 0 failed
  merkle roots   : 31 recomputed, 0 failed
  inclusion      : 4212 anchored, 0 failed, 0 not yet anchored
  OTS receipts   : 31/31 anchors carry a receipt

PASS — all offline cryptographic checks succeeded.
```

Exit code `0` = PASS. Anything else = the bundle is inconsistent, and the
output names the exact trace or anchor that broke.

## What it checks

1. **Binding** — recomputes `final_proof = SHA-256(reasoning_hash || "||" || exchange_tx_id)`
   for every bound trace.
2. **Anchor integrity** — recomputes every anchor's Merkle root from its
   full leaf list.
3. **Inclusion** — confirms every trace's `reasoning_hash` is present in the
   anchor covering its sealing time. A trace silently edited, inserted, or
   deleted after anchoring cannot pass.

The final step — proving each Merkle root existed before a specific Bitcoin
block — uses the standard OpenTimestamps client against receipts embedded
in the bundle:

```
irl-verify bundle.json --dump-ots ./ots
ots verify ./ots/anchor-0.ots
```

## What it proves (and what it doesn't)

A passing bundle proves **existence, integrity, temporal order, binding,
and independence** of the recorded decisions. It does *not* prove the
agent's self-reported snapshot was honest at sealing time — it proves
nothing was changed afterward, and that the producer cannot rewrite
history even with full control of their own database. See
[SPEC.md §6](SPEC.md#6-threat-model-summary) for the threat model.

## Install

```
cargo install --git https://github.com/GabrielGauss/irl-verify
```

or build from source:

```
git clone https://github.com/GabrielGauss/irl-verify
cd irl-verify && cargo build --release
./target/release/irl-verify --help
```

## Usage

```
irl-verify <bundle.json>                # verify, human-readable report
irl-verify <bundle.json> --json        # machine-readable report
irl-verify <bundle.json> --dump-ots d  # extract OTS receipts for `ots verify`
```

## The spec

The bundle format and verification algorithm are fully defined in
[SPEC.md](SPEC.md) (frozen at v1). This crate is a reference
implementation written *from the spec* — it shares no code with the IRL
Engine. Reimplement it in your language of choice; if your implementation
and this one disagree, file an issue.

Bundles are exported from any IRL deployment via:

```
GET /irl/attestation?from=<rfc3339>&to=<rfc3339>[&agent_id=<uuid>]
```

A public anchor transparency feed (no auth) is available at
`GET /irl/anchors` on any IRL instance, e.g.
[irl.macropulse.live/irl/anchors](https://irl.macropulse.live/irl/anchors).

## License

MIT — verification infrastructure should be free for everyone, forever.
