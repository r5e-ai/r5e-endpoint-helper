# `r5e-endpoint-helper`

Managed-endpoint supervisor, local MCP/subprocess Cedar policy gate, off-path session observer, and transparent user disclosure for **R5E**.

## Purpose & Honest Trust Boundary

A network gateway alone sees only HTTP requests routed through it; it never sees local shell commands (`bash -c ...`), scripts an agent writes after a gateway refusal, local `stdio` MCP tool servers, or sessions run directly against a personal subscription.

`r5e-endpoint-helper` closes those managed-endpoint blind spots using the **exact same `cedar-policy = "=4.9.1"` engine** as the R5E Gateway:

1. **Zero-Login On-Device Disclosure (`disclosure`)**: Tells the laptop user offline and in plain words who deployed the helper, which harness binaries are watched, what leaves the machine, what is **never** read (browser, mail, unrelated terminals, untouched files), retention and reader rules, and the ring buffer of the last items sent.
2. **Pre-Execution Local Subprocess & MCP `stdio` Gate (`exec-gate`, `mcp-wrap`)**:
   - In **`enforce`** mode, stops policy-withheld local shell commands and local MCP `tools/call` invocations *before* they execute, returning a structured policy reason to the harness and recording `"prevented"`.
   - In **`observe`** mode, allows execution and records `"observed"` (and correlates post-refusal script workarounds to the same `urn:r5e:session:...`).
   - Computes and pins SHA-256 digests of local MCP `tools/list` descriptors (`mcp_descriptor_sha256`) so mid-session MCP tool-description rug-pulls are caught locally.
   - Evaluates cached Cedar policies offline and marks any offline window explicitly when replaying buffered records.
3. **Provenance v2 Signing (`attestation`)**: Derives `key:ed25519:sha256:<hex>`, `key:es256:sha256:<hex>`, and `key:es384:sha256:<hex>` key identifiers and signs `DSSEv1` (`application/vnd.r5e.provenance-evidence+json;v=2`) envelopes across all 28 base `provenance.r5e.io/v2/*` and `core.r5e.io/v1/*` definitions.
4. **Operator Deployment Claim & Gateway Grant Ceremony (`claim`, `grant-gateway`, `deployment-status`)**: Verifies `ChainStarted`, `DefinitionPublished`, and draft `Deployment` offline before co-signing with the customer's root key (`POST /v1/deployment/claim/prepare` + `finalize`), guards against accidental permanent root lock-in (`--generate-recovery-key <path>` with `0600` private key mode or explicit `--allow-permanent-roots`), and issues/renews root `Endorsement` grants (`POST /v1/deployment/grants`) with zero secret exposure in CLI arguments, stdout/stderr, or receipts.
5. **Operator Root Rotation Ceremony (`propose-root-change`, `approve-root-change`, `apply-root-change`)**: Authors offline `RootsChanged` proposals (`quorum` or one-time `recovery`), co-signs 2-signer custodian `RootChangeApproval` records (`[root, custodianKey]`) with veto-free quorum conflict guards, submits verified proposals to `POST /v1/deployment/roots`, and immediately re-endorses `gatewayKey` (`EpochSeal` + working kinds) via `--grant-gateway-with`.
6. **Operator Grant Revocation Ceremony (`revoke-grant`)**: Mints and submits single-record `Revocation` envelopes (`seq: 1`, `previous: null`) on `urn:r5e:stream:<deployment>:authority:revocation:<token>` under exact-`streamPrefix` self-describing capture profiles (`POST /v1/deployment/revocations` or `--dry-run-out <file>`), supporting both explicit `--target <ref>` and `--issuer <keyid>` (`--from-root-keyid`) batch revocation of all unrevoked grants advertised in `GET /v1/deployment` (`grants`), while clamping microsecond `capturedAt` against `GET /v1/deployment` (`deploymentRecord` / latest start head). *Operational safety note*: when rotating gateway grants, submit the replacement grant (`grant-gateway`) **before** revoking the old grant (`revoke-grant`) unless intentionally stripping all gateway standing.
7. **Two-Signer Retention Hold Release Ceremony (`grant-releaser`, `release-hold`)**: Issues collision-free root `Endorsement` grant sets (`urn:r5e:stream:<deployment>:authority:root:<hex>:grant:<token>`, `seq: 1`, `previous: null`, `mayEndorse: false`) authorizing a counsel / hold-releaser key on `urn:r5e:stream:<deployment>:retention`, and drives the Bearer-authenticated 2-step `POST /v1/evidence/retention/holds/release/{prepare,finalize}` co-signing ceremony with strict offline verification of `kind == "RetentionHoldRelease"`, distinct recorder `issuer`, and `body.{hold, reason, releasedBy}` before counsel signs anything (never accepting raw bearer tokens on CLI argv and never printing bearer headers or private seeds).
8. **Workload Session Opening, Batch Record Shipping, Exact Retention Parity & Badge Revocation (`enrol-badge`, `open-session`, `record-event` / `record-and-ship`, `ship-bundle`, `revoke-badge`)**: Enrols ephemeral Ed25519 workload `Badge`s (copying `"retention"` verbatim from the gateway's `CaptureProfile` into the helper's local `r5e.capture-profile/v2` blob, hashing `--cedar-policy` into `deploymentPolicyRef`, setting `--require-policy-for-tools` `policyRequiredKinds`, and persisting state + seed with `0600` permissions), opens gateway-anchored sessions (`POST /v1/evidence/sessions`), appends and auto-chunks workload operational records (`<= 64` records and `< 6 MiB` per batch) to `POST /v1/evidence/records` with `--omit-payload-blobs` missing-content tolerance and idempotent `already_admitted` replay, and revokes badges via `POST /v1/authority/badges/revoke`.
9. **End-to-End Cedar-Gated Subprocess Wrapper, Live `stdio` MCP Proxy & Durable `0600` Offline Outbox (`exec`, `mcp-proxy`, `flush-outbox`)**: Synchronously gates child processes (`exec`) and live `stdio` JSON-RPC 2.0 MCP servers (`mcp-proxy`, with canonical `tools/list` pinning, `arguments_sha256` Cedar context, and `--block-rug-pull` latched quarantine), signs linked `PolicyDecision` -> `ToolCall` (`body.policy.decisionRef`) -> `ToolResult` (`body.call`) and `Observation` (`mcp_tools_pinned` / `mcp_descriptor_rug_pull`) streams satisfying `profile_bounds`, spools unshipped batches into a `0700`/`0600` `--outbox` when offline, and flushes them via `flush-outbox`.

### Non-Confinement Statement (Always Carried)

Endpoint supervision is stronger than a network gateway alone on a managed laptop, and it is **not** hostile-root confinement: an administrator on the laptop can stop, bypass, or tamper with a local helper. Coverage statements for helper-enrolled laptops carry this boundary explicitly; full workload confinement is claimed only when R5E's runtime hosts the workload directly.

## `r5e-api` Block 0 Founding Artifacts

[`genesis/`](genesis/) carries the public founding artifacts of the live `r5e-api` provenance chain (`evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5`, minted `2026-11-22T04:12:28.994536Z`):

| File | Description | Identifier / SHA-256 |
|---|---|---|
| [`genesis/block-0-r5e-api.json`](genesis/block-0-r5e-api.json) | `r5e.provenance-export/v2` Block 0 bundle for `r5e-api` (9 founding records, 122/122 checks `ok`) | `sha256:a706c2bc8e4705e57e316d4549d3d0733290d242aefca3016f80ac824cf0d55a` |
| [`genesis/publications.json`](genesis/publications.json) | Published base `provenance.r5e.io/v2/*` & `core.r5e.io/v1/*` definitions | `sha256:b26f95e10df37756cf04217d6a739138e0e188ed3ac3c01214054e19440b13f9` |
| [`genesis/r5e-root.pub.pem`](genesis/r5e-root.pub.pem) | Founding root public key (Ed25519) | `key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc` |
| [`genesis/r5e-publisher.pub.pem`](genesis/r5e-publisher.pub.pem) | Founding definition-publisher public key for `r5e.io` (ES256) | `key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33` |

Verified by three independent implementations (the Elixir reference implementation, clean-room Python `r5e-verify-py`, and clean-room Rust `r5e-verify-rs` — the latter two written from the specification and conformance vectors without reading the reference implementation), exercised across six execution surfaces (Elixir in-process, Gateway HTTP `/v1/evidence/verify`, an independent second-operator clean-tree run of the reference verifier, Python CLI, Rust native CLI, and zero-import WebAssembly), all producing byte-identical canonical report `c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed` (`122 ok / 0 failed / 0 incomplete`).

## Build & Test

```sh
cargo test --locked
```

When [`r5e-spec`](../r5e-spec) is checked out beside this repository (`../r5e-spec/definitions`, or overridden via `R5E_DEFINITIONS_DIR`), all `48/48` unit and ceremony integration tests run out of the box. Optional cross-repo subprocess checks against `r5e-verify-py` (`../r5e-verify-py`, or `R5E_VERIFY_PY_DIR`) and `r5e-verify-rs` (`../r5e-verify-rs/target/release/recurse_verify`, or `R5E_VERIFY_RS_BIN`) run automatically when built and skip gracefully otherwise (while failing closed if explicitly configured via environment variable).

## Contributing & License

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CLA.md`](CLA.md). Licensed under GNU Affero General Public License v3.0 only (`AGPL-3.0-only`) — see [`LICENSE`](LICENSE).
