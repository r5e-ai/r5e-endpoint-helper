use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use r5e_endpoint_helper::attestation::{
    base_v2_schema_map, bytes_ref, decode_strict_base64, ed25519_key_id, encode_canonical_json,
    generate_os_random_bytes, generate_os_random_seed_32, parse_ed25519_signing_key_bytes,
    sign_v2_record_multi, truncate_utf8_bytes, validate_call_id, write_private_key_file_0600,
    BlobEntry, EnrolledSessionOptions, PublicKeyEntry, SubjectPublicKey, MAX_DETAILS_VALUE_BYTES,
};
use r5e_endpoint_helper::claim_http::{
    build_grant_revocations_batch, build_root_gateway_grant, ceil_to_micros,
    default_gateway_grant_kinds, default_workload_badge_kinds, execute_claim_ceremony,
    finalize_detached_claim_ceremony, finalize_detached_endorsement, finalize_detached_principal,
    get_deployment_status, get_deployment_status_raw, latest_status_captured_at_utc,
    merge_submit_grants_requests, prepare_detached_claim_ceremony, prepare_detached_endorsement,
    prepare_detached_principal, record_captured_at_utc, select_unrevoked_grants_by_issuer,
    submit_deployment_grants, submit_deployment_revocations, ClaimClientConfig, CustodianEntry,
    DetachedEndorsementParams, DetachedPrincipalParams, GatewayGrantParams, PrepareClaimRequest,
    PrepareClaimRootEntry, PreparedClaimCeremony, PreparedEndorsement, PreparedPrincipal,
    SubmitGrantsRequest, REVOCATION_ROTATION_SAFETY_NOTE,
};
use r5e_endpoint_helper::crypto_keys::{
    check_piv_ed25519_pae_limit, parse_public_key_entry, parse_public_key_material,
    SignatureAlgorithm, PIV_HARDWARE_ED25519_MAX_PAE_BYTES,
};
use r5e_endpoint_helper::disclosure::{
    HelperDisclosure, NEVER_COLLECTED, SUPERVISION_BOUNDARY_STATEMENT,
};
use r5e_endpoint_helper::enrolment_http::{
    enrol_endpoint_badge, enrol_endpoint_badge_with_options, EnrolBadgeOptions,
    EnrolmentClientConfig,
};
use r5e_endpoint_helper::evidence_http::{
    build_ship_request_from_recorder, flush_outbox_over_http_with_key,
    load_ship_request_from_bundle_path, normalize_workload_kind, open_session_over_http,
    persist_outbox_and_ship_state_with_key, revoke_badge_over_http, ship_records_over_http,
    EnrolledStateFile, OpenSessionRequest, OutboxQueueFile,
};
use r5e_endpoint_helper::hold_release::{
    build_releaser_grant, execute_release_hold_ceremony, HoldReleaseClientConfig,
    ReleaserGrantParams,
};
use r5e_endpoint_helper::mcp_stdio::{
    canonical_tool_arguments_digest, ClientFrameDisposition, McpStdioSessionGuard,
};
use r5e_endpoint_helper::offline_badge::{
    cosign_prepared_offline_workload_badge,
    cosign_prepared_offline_workload_badge_with_external_signature, mint_offline_workload_badge,
    prepare_offline_workload_badge_with_alg, OfflineWorkloadBadgeParams,
    PreparedOfflineWorkloadBadge, DEFAULT_OFFLINE_CEDAR_POLICY,
    EPHEMERAL_DELEGATOR_REVOCATION_NOTE,
};
use r5e_endpoint_helper::outbox_cipher::{
    resolve_optional_outbox_key, OutboxKey, OUTBOX_KEY_ENV_VAR,
};
use r5e_endpoint_helper::policy_gate::{hex_lower, LocalActionKind, LocalCedarGate, Posture};
use r5e_endpoint_helper::publication::{
    encode_carried_publication_set_canonical, finalize_publication,
    prepare_publication_with_piv_guard, write_atomic_file, PreparePublicationParams,
    PreparedPublication,
};
use r5e_endpoint_helper::root_rotation::{
    apply_root_change, apply_root_change_with_grant_request, approve_root_change,
    finalize_detached_root_approval, finalize_detached_root_change, prepare_detached_root_approval,
    prepare_detached_root_change, propose_root_change, ApproveRootChangeParams,
    PreparedRootApproval, PreparedRootChange, ProposeRootChangeParams, RootChangeAuthorization,
    RootChangeProposalFile, IRREVERSIBLE_CLAIM_WARNING,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};
use std::sync::mpsc;
use std::thread;

#[derive(Parser)]
#[command(
    name = "r5e-endpoint-helper",
    about = "Managed-endpoint supervisor, local MCP/subprocess Cedar gate, deployment claim ceremony, and transparent user disclosure"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliPosture {
    Observe,
    Enforce,
}

impl From<CliPosture> for Posture {
    fn from(value: CliPosture) -> Self {
        match value {
            CliPosture::Observe => Posture::Observe,
            CliPosture::Enforce => Posture::Enforce,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliAuthorizationMode {
    Quorum,
    Recovery,
}

impl From<CliAuthorizationMode> for RootChangeAuthorization {
    fn from(value: CliAuthorizationMode) -> Self {
        match value {
            CliAuthorizationMode::Quorum => RootChangeAuthorization::Quorum,
            CliAuthorizationMode::Recovery => RootChangeAuthorization::Recovery,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliHookClient {
    Antigravity,
    ClaudeCode,
    Codex,
}

impl From<CliHookClient> for r5e_endpoint_helper::agent_hooks::HookClient {
    fn from(value: CliHookClient) -> Self {
        match value {
            CliHookClient::Antigravity => Self::Antigravity,
            CliHookClient::ClaudeCode => Self::ClaudeCode,
            CliHookClient::Codex => Self::Codex,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliHookMode {
    Observe,
    Enforce,
}

impl From<CliHookMode> for r5e_endpoint_helper::agent_hooks::HookMode {
    fn from(value: CliHookMode) -> Self {
        match value {
            CliHookMode::Observe => Self::Observe,
            CliHookMode::Enforce => Self::Enforce,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Print the offline, zero-login privacy and collection disclosure for this laptop.
    Disclosure {
        #[arg(long, default_value = "Organisation Security Team")]
        deployed_by: String,
        #[arg(long, default_value = "2026-11-11")]
        deployed_at: String,
        #[arg(long, value_enum, default_value_t = CliPosture::Enforce)]
        posture: CliPosture,
        #[arg(long)]
        json: bool,
    },
    /// Gate a child command emitted by a watched harness against a local Cedar policy bundle
    /// before executing it.
    ExecGate {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long, value_enum, default_value_t = CliPosture::Enforce)]
        posture: CliPosture,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        session: String,
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Wrap a local `stdio` MCP tool server, pinning `tools/list` descriptors and gating
    /// `tools/call` frames through the local Cedar policy before forwarding to child stdin.
    McpWrap {
        #[arg(long)]
        server_id: String,
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long, value_enum, default_value_t = CliPosture::Enforce)]
        posture: CliPosture,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        session: String,
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Enrol an ephemeral Ed25519 Badge against a running `recurse_gateway` (`POST /v1/authority/badges/prepare`
    /// -> `finalize`), record a session `SessionOpened` + `SessionClosed`, and write a canonical
    /// `r5e.provenance-export/v2` bundle for independent verification.
    /// Reads bearer auth from environment variable `token_env` (default `R5E_TOKEN`), never CLI argv.
    EnrolSmoke {
        #[arg(long)]
        gateway_url: String,
        #[arg(long, default_value = "R5E_TOKEN")]
        token_env: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = "endpoint-helper")]
        holder: String,
        #[arg(long, default_value = "urn:r5e:agent:endpoint-smoke")]
        actor: String,
        #[arg(long, default_value = "urn:r5e:session:endpoint-smoke")]
        session: String,
        #[arg(long)]
        out_bundle: PathBuf,
    },
    /// Inspect a gateway node's public deployment status (`GET /v1/deployment`).
    DeploymentStatus {
        #[arg(long)]
        gateway_url: String,
    },
    /// Execute the operator Deployment Claim (& optional Gateway Grant) Ceremony (`A6-claim-exchange.md`).
    ///
    /// Zero secrets in CLI argv or stdout/logs:
    /// - Claim code is read from `--claim-code-file` or env `--claim-code-env` (default `R5E_CLAIM_CODE`).
    /// - Claiming root seed is read from `--root-seed-file` or env `--root-seed-env` (default `R5E_ROOT_SEED_B64`),
    ///   or generated via `/dev/urandom` into `--generate-root-seed-out` with mode `0600`.
    Claim {
        #[arg(long)]
        gateway_url: String,
        #[arg(long)]
        claim_code_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_CLAIM_CODE")]
        claim_code_env: String,
        #[arg(long)]
        root_seed_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_ROOT_SEED_B64")]
        root_seed_env: String,
        #[arg(long)]
        generate_root_seed_out: Option<PathBuf>,
        /// Optional holder label for the claiming root (e.g. `person`, `organization`).
        #[arg(long)]
        holder: Option<String>,
        /// Optional custody label for the claiming root (e.g. `hardware`, `software`).
        #[arg(long)]
        custody: Option<String>,
        /// Optional URI identity for the claiming root (e.g. `mailto:lena@example.com`).
        #[arg(long)]
        identity: Option<String>,
        /// Optional JSON file containing an array of root objects `{publicKey, holder?, custody?, identity?}`.
        /// May either list all roots (including the claiming root) or only co-roots.
        #[arg(long)]
        roots_file: Option<PathBuf>,
        /// Repeatable additional root entry (JSON `{publicKey, holder?, custody?, identity?}` or base64 Ed25519 pubkey).
        #[arg(long = "additional-root")]
        additional_roots: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        /// Repeatable standby recovery key ID (`key:ed25519:sha256:...`).
        #[arg(long = "recovery-key")]
        recovery_keys: Vec<String>,
        /// Generate a fresh Ed25519 standby recovery keypair (`0600` private key at `<PATH>`, never printed)
        /// and include its `key:ed25519:sha256:...` fingerprint in `recoveryKeys`.
        #[arg(long = "generate-recovery-key")]
        generate_recovery_keys: Vec<PathBuf>,
        /// Repeatable custodian specification (`<identity>[=<keyid>]`, `<identity>[,<keyid>]`, or JSON `{"identity":"...","key":"..."}`).
        #[arg(long = "custodian")]
        custodians: Vec<String>,
        /// Explicitly confirm claiming a deployment with zero recovery keys and zero custodians
        /// (permanent roots that can NEVER be rotated on this chain).
        #[arg(long, default_value_t = false)]
        allow_permanent_roots: bool,
        /// Allow overwriting existing generated key files (`--generate-root-seed-out` / `--generate-recovery-key`).
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Repeatable trusted publisher key ID (`key:ed25519:sha256:...`).
        #[arg(long = "trusted-publisher")]
        trusted_publishers: Vec<String>,
        /// Explicitly allow claiming when no `--trusted-publisher` pin is supplied.
        #[arg(long, default_value_t = false)]
        allow_untrusted_publisher: bool,
        /// Sign and `POST /v1/deployment/grants` immediately after `finalize` (default `true`; override with `--skip-gateway-grant` or `--grant-gateway=false`).
        #[arg(
            long,
            num_args = 0..=1,
            default_value_t = true,
            default_missing_value = "true"
        )]
        grant_gateway: bool,
        /// Skip `POST /v1/deployment/grants` after `finalize` (claim only).
        #[arg(long, default_value_t = false)]
        skip_gateway_grant: bool,
        #[arg(long, default_value_t = 2_592_000)]
        grant_ttl_seconds: u64,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        grant_actor: String,
        #[arg(long, value_delimiter = ',')]
        grant_kinds: Option<Vec<String>>,
        /// Optional path to write the full canonical JSON claim receipt.
        #[arg(long)]
        out_receipt: Option<PathBuf>,
    },
    /// Build, sign, and submit (`POST /v1/deployment/grants`) a root `Endorsement` for a claimed
    /// gateway's working key (`urn:r5e:stream:<deployment>:authority:root:<root_hex>`).
    GrantGateway {
        #[arg(long)]
        gateway_url: String,
        #[arg(long)]
        root_seed_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_ROOT_SEED_B64")]
        root_seed_env: String,
        /// Gateway working key ID (`key:ed25519:sha256:...`). If omitted, queried from `GET /v1/deployment`.
        #[arg(long)]
        gateway_key_id: Option<String>,
        /// Deployment slug (e.g. `acme-prod`). Used to construct `urn:r5e:stream:<deployment>:` when `--stream-prefix` is omitted.
        #[arg(long)]
        deployment: Option<String>,
        /// Full deployment stream prefix (`urn:r5e:stream:<deployment>:`). If omitted, derived from `--deployment` or `GET /v1/deployment`.
        #[arg(long)]
        stream_prefix: Option<String>,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        /// Required when `--seq > 1`: previous `Endorsement` reference (`evidence:sha256:...`) on this root's grant stream.
        #[arg(long)]
        previous: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        #[arg(long, value_delimiter = ',')]
        kinds: Option<Vec<String>>,
        /// Optional explicit RFC 3339 `Endorsement.body.notBefore` timestamp; defaults to `now - 60s`.
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long, default_value_t = 2_592_000)]
        ttl_seconds: u64,
        #[arg(
            long,
            num_args = 0..=1,
            default_value_t = true,
            default_missing_value = "true"
        )]
        may_endorse: bool,
        /// Optional path to write the canonical `SubmitGrantsRequest` JSON payload.
        #[arg(long)]
        out_grant_file: Option<PathBuf>,
    },
    /// Build, sign, and submit (`POST /v1/deployment/revocations`) one or more
    /// `provenance.r5e.io/v2/Revocation` records revoking prior `Endorsement` or `Badge` grants
    /// on unique single-record streams `urn:r5e:stream:<deployment>:authority:revocation:<token>`.
    ///
    /// Pass `--target <evidence:sha256:...>` (repeatable) and/or `--issuer <key:ed25519:sha256:...>`
    /// (alias `--from-root-keyid`) to select all unrevoked grants issued by a retired root from
    /// `GET /v1/deployment` (`grants`) and batch up to 16 revocations in one request.
    ///
    /// Operational safety note: When rotating gateway grants, submit the replacement grant
    /// (`grant-gateway`) BEFORE revoking the old grant (`revoke-grant`) unless intentionally
    /// stripping all gateway standing.
    RevokeGrant {
        /// Gateway base URL (e.g. `http://127.0.0.1:4000`). Required unless `--dry-run-out` is passed
        /// without `--issuer` alongside `--deployment` or `--stream-prefix`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Repeatable target `Endorsement` or `Badge` evidence reference (`evidence:sha256:...`) to revoke.
        /// May be omitted when `--issuer` (`--from-root-keyid`) is supplied.
        #[arg(
            long = "target",
            visible_aliases = ["grant-ref", "endorsement-ref", "badge-ref"]
        )]
        targets: Vec<String>,
        /// Select all held unrevoked grants with `grant.issuer == <KEYID>` from `GET /v1/deployment` (`grants`).
        #[arg(
            long,
            visible_aliases = ["from-root-keyid", "issuer-key-id"]
        )]
        issuer: Option<String>,
        /// Optional non-empty human-readable revocation reason (`Revocation.body.reason`).
        #[arg(long)]
        reason: Option<String>,
        /// Entitled signing private key file (current root seed/PEM, or issuer/subject private key).
        #[arg(
            long = "root-key-file",
            visible_aliases = ["signer-key-file", "key-file", "root-seed-file", "signer-key"]
        )]
        root_key_file: Option<PathBuf>,
        /// Fallback environment variable holding base64/PEM private key when `--root-key-file` is omitted.
        #[arg(long, default_value = "R5E_ROOT_SEED_B64")]
        root_seed_env: String,
        /// Deployment slug (e.g. `acme-prod`). Used to construct `urn:r5e:stream:<deployment>:` when `--stream-prefix` is omitted.
        #[arg(long)]
        deployment: Option<String>,
        /// Full deployment stream prefix (`urn:r5e:stream:<deployment>:`). If omitted, derived from `--deployment` or `GET /v1/deployment`.
        #[arg(long)]
        stream_prefix: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        /// Write the canonical `{records, keys, blobs}` revocation payload to `<PATH>` without `POST`ing to `--gateway-url`.
        #[arg(long)]
        dry_run_out: Option<PathBuf>,
        /// Optional path to write a copy of the canonical `{records, keys, blobs}` revocation payload alongside live submission.
        #[arg(long)]
        out_revocation_file: Option<PathBuf>,
    },
    /// Offline operator command to mint `R5E_EVIDENCE_AUTHORITY_FILE` (`{"records": [{ref, envelope}], "keys": [...], "blobs": [profile]}`)
    /// containing a root `Endorsement` (`mayEndorse: true`) for a `recurse_gateway` deployment key.
    MintGatewayAuthority {
        #[arg(long)]
        gateway_key_id: String,
        #[arg(long, default_value = "default")]
        deployment: String,
        #[arg(long, default_value = "urn:r5e:operator:security")]
        actor: String,
        #[arg(long, value_delimiter = ',')]
        kinds: Option<Vec<String>>,
        #[arg(long, default_value_t = 86_400 * 30)]
        ttl_seconds: u64,
        #[arg(long)]
        root_seed_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_ROOT_SEED_B64")]
        root_seed_env: String,
        #[arg(long)]
        generate_root_seed_out: Option<PathBuf>,
        #[arg(long)]
        out_authority_file: PathBuf,
    },
    /// Offline ceremony step 1 (`A6-slice2-roots-changed.md`): build and DSSE-sign a proposed
    /// `provenance.r5e.io/v2/RootsChanged` record on `urn:r5e:stream:<deployment>:start` at `seq >= 3`.
    ProposeRootChange {
        #[arg(long)]
        deployment: String,
        /// Chain reference (`evidence:sha256:...` of the `Deployment` record at `seq = 2`).
        #[arg(long)]
        chain: String,
        /// Immediately preceding start-stream record reference (`Deployment` at `seq = 2` or prior `RootsChanged`).
        #[arg(long)]
        replaces: String,
        /// Target start-stream sequence position (`>= 3`).
        #[arg(long)]
        seq: u64,
        #[arg(long, value_enum)]
        authorization: CliAuthorizationMode,
        /// Proposing root private key (for `quorum`) or standby recovery private key being spent (for `recovery`).
        #[arg(long)]
        signer_key: PathBuf,
        /// Repeatable new root specification: PEM/seed/pubkey file path (optional `;holder=...;custody=...;identity=...`),
        /// base64 Ed25519 public key, or JSON `{publicKey, holder?, custody?, identity?}`.
        #[arg(long = "root-key")]
        root_keys: Vec<String>,
        /// Optional JSON file containing an array of root objects `{publicKey, holder?, custody?, identity?}`.
        #[arg(long)]
        roots_file: Option<PathBuf>,
        /// Optional repeatable additional root entry (alias matching `claim`).
        #[arg(long = "additional-root")]
        additional_roots: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        /// Repeatable standby recovery key ID (`key:ed25519:sha256:...`) under the new terms.
        #[arg(long = "recovery-key")]
        recovery_keys: Vec<String>,
        /// Generate a fresh Ed25519 standby recovery keypair (`0600` private key at `<PATH>`, never printed)
        /// and include its `key:ed25519:sha256:...` fingerprint in `recoveryKeys`.
        #[arg(long = "generate-recovery-key")]
        generate_recovery_keys: Vec<PathBuf>,
        /// Allow overwriting existing `--generate-recovery-key` files.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Repeatable custodian specification (`<identity>[=<keyid>]`, `<identity>[,<keyid>]`, or JSON).
        #[arg(long = "custodian")]
        custodians: Vec<String>,
        /// Optional human-readable reason recorded in `RootsChanged.body.reason`.
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        /// Optional override for `provenance.r5e.io/v2/RootsChanged` `schemaRef`.
        #[arg(long)]
        roots_changed_schema_ref: Option<String>,
        /// Optional override for `provenance.r5e.io/v2/RootChangeApproval` `schemaRef` in the capture profile.
        #[arg(long)]
        approval_schema_ref: Option<String>,
        /// Optional custom `RootsChanged` kind-definition JSON file to bundle in `blobs` when overriding `schemaRef`.
        #[arg(long)]
        roots_changed_definition_file: Option<PathBuf>,
        /// Output path for the canonical `RootChangeProposalFile` JSON.
        #[arg(long)]
        out: PathBuf,
    },
    /// Offline ceremony step 2 (`A6-slice2-roots-changed.md`): co-sign a 2-signature
    /// `provenance.r5e.io/v2/RootChangeApproval` (`signatures: [root, custodianKey]`) and append it to a quorum proposal.
    ApproveRootChange {
        /// Path to the `proposal.json` produced by `propose-root-change`.
        #[arg(long)]
        proposal: PathBuf,
        /// Current root private key file (Signer 1 / `issuer`).
        #[arg(long)]
        root_key: PathBuf,
        /// Named custodian identity URI (e.g. `mailto:lena@example.com`).
        #[arg(long)]
        custodian: String,
        /// Named custodian's personal Ed25519 private key file (Signer 2).
        #[arg(long)]
        custodian_key: PathBuf,
        /// Optional human-readable reason recorded in `RootChangeApproval.body.reason`.
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:custodian")]
        actor: String,
        /// Optional override for `provenance.r5e.io/v2/RootChangeApproval` `schemaRef`.
        #[arg(long)]
        approval_schema_ref: Option<String>,
        /// Optional custom `RootChangeApproval` kind-definition JSON file to bundle in `blobs` when overriding `schemaRef`.
        #[arg(long)]
        approval_definition_file: Option<PathBuf>,
        /// Output path for the updated proposal JSON (updates `--proposal` in-place when omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ceremony step 3 (`A6-slice2-roots-changed.md` §§4.4 & 5.4): submit `{change, approvals, keys, blobs}`
    /// to `POST /v1/deployment/roots` and (strongly recommended via `--grant-gateway-with`) immediately
    /// endorse the gateway's working/sealer key under a new or remaining root (`POST /v1/deployment/grants`)
    /// so pre-rotation seals stay qualifying and `Sealer` continues sealing without interruption.
    ApplyRootChange {
        #[arg(long)]
        gateway_url: String,
        #[arg(long)]
        proposal: PathBuf,
        /// Recommended operational default (`A6-slice2-roots-changed.md` §4.4): private key file of a
        /// newly added or remaining root used to immediately issue & `POST /v1/deployment/grants` covering
        /// `EpochSeal` + gateway working kinds so pre-rotation seals remain qualifying.
        #[arg(long)]
        grant_gateway_with: Option<PathBuf>,
        /// Optional pre-signed `{records, keys, blobs}` `SubmitGrantsRequest` JSON file (e.g. produced by
        /// `finalize-endorsement` with an external `es256` hardware root) submitted immediately after `POST /v1/deployment/roots`.
        #[arg(long = "grant-file")]
        grant_file: Option<PathBuf>,
        /// Optional gateway working key ID override (`key:<alg>:sha256:...`); queried from `GET /v1/deployment` when omitted.
        #[arg(long)]
        gateway_key_id: Option<String>,
        /// Optional explicit RFC 3339 `Endorsement.body.notBefore` timestamp for the gateway grant;
        /// when omitted, automatically derived from `GET /v1/deployment` (`chainStarted` / `deploymentRecord` `capturedAt - 60s`)
        /// so pre-rotation `EpochSeal` records remain within the new root's endorsement window.
        #[arg(long)]
        grant_not_before: Option<String>,
        #[arg(long, default_value_t = 2_592_000)]
        grant_ttl_seconds: u64,
        #[arg(long, default_value_t = 1)]
        grant_seq: u64,
        #[arg(long)]
        grant_previous: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        grant_actor: String,
        #[arg(long, value_delimiter = ',')]
        grant_kinds: Option<Vec<String>>,
    },
    /// Build (and optionally submit) a root `Endorsement` (`mayEndorse: false`) granting a
    /// counsel / hold-releaser public key standing to co-sign `RetentionHoldRelease` records on
    /// `urn:r5e:stream:<deployment>:retention` (`A7` §3.2).
    ///
    /// Emits a canonical `{records, keys, blobs}` grant set on a collision-free sub-stream
    /// `urn:r5e:stream:<deployment>:authority:root:<last_hex>:grant:<16hex_token>` (`seq: 1`,
    /// `previous: null`) so a root that already issued the gateway grant at `seq: 1` never hits
    /// `:stream_fork_refused`. When `--gateway-url` is provided, discovers `deployment` from
    /// `GET /v1/deployment` and clamps `capturedAt` / `notBefore` `>= ceil_to_micros(startHead)`.
    GrantReleaser {
        /// Optional gateway base URL (`http://127.0.0.1:4000`) used to discover `deployment` and
        /// clamp microsecond timestamps against `GET /v1/deployment`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Deployment slug (e.g. `acme-prod`). Required when `--gateway-url` and `--stream-prefix` are omitted.
        #[arg(long)]
        deployment: Option<String>,
        /// Optional full deployment stream prefix (`urn:r5e:stream:<deployment>:`).
        #[arg(long)]
        stream_prefix: Option<String>,
        /// Current root signing private key file (32B raw/base64 seed or PKCS#8 PEM).
        #[arg(
            long = "root-key-file",
            visible_aliases = ["root-seed-file", "signer-key-file", "key-file", "signer-key"]
        )]
        root_key_file: Option<PathBuf>,
        /// Fallback environment variable holding base64/PEM root private key when `--root-key-file` is omitted.
        #[arg(long, default_value = "R5E_ROOT_SEED_B64")]
        root_seed_env: String,
        /// Counsel / releaser Ed25519 public key file (SPKI PEM, 32B raw/base64 pubkey, or `{algorithm, bytes}` JSON).
        #[arg(
            long = "releaser-pubkey-file",
            visible_aliases = ["subject-pubkey-file", "counsel-pubkey-file"]
        )]
        releaser_pubkey_file: Option<PathBuf>,
        /// Counsel / releaser Ed25519 private seed/PEM file (derives public key safely without printing seed).
        #[arg(
            long = "releaser-key-file",
            visible_aliases = ["releaser-seed-file", "counsel-key-file"]
        )]
        releaser_key_file: Option<PathBuf>,
        /// Optional explicit `key:ed25519:sha256:...` fingerprint of the counsel / releaser key.
        #[arg(
            long = "releaser-key-id",
            visible_aliases = ["subject", "counsel-key-id"]
        )]
        releaser_key_id: Option<String>,
        /// Granted kind(s); defaults to `provenance.r5e.io/v2/RetentionHoldRelease`.
        #[arg(long = "kind", visible_alias = "kinds", value_delimiter = ',')]
        kinds: Option<Vec<String>>,
        /// Optional `Endorsement.body.actorPrefixes` (omitted by default per `A7` §3.2 so the gateway's `:retention` actor is covered).
        #[arg(
            long = "actor-prefix",
            visible_alias = "actor-prefixes",
            value_delimiter = ','
        )]
        actor_prefixes: Vec<String>,
        /// Optional `Endorsement.body.actsFor` URI (omitted by default per `A7` §3.2).
        #[arg(long)]
        acts_for: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        /// Optional token suffix for `:authority:root:<hex>:grant:<token>` (defaults to 8 OS-random bytes as 16 lowercase hex chars).
        #[arg(long)]
        grant_token: Option<String>,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long)]
        previous: Option<String>,
        /// Optional explicit RFC 3339 `Endorsement.body.notBefore` override.
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long, default_value_t = 2_592_000)]
        ttl_seconds: u64,
        /// Output path for the canonical `{records, keys, blobs}` grant JSON file.
        #[arg(
            long = "out-grant-file",
            visible_aliases = ["out", "out-authority-file"]
        )]
        out_grant_file: PathBuf,
        /// Also `POST` the generated grant set to `<gateway-url>/v1/deployment/grants`.
        #[arg(long, default_value_t = false)]
        submit: bool,
    },
    /// Execute the 2-step DSSE co-signing Retention Hold Release ceremony (`A7` §3.2) against
    /// `POST /v1/evidence/retention/holds/release/{prepare,finalize}`.
    ///
    /// Zero secrets in CLI argv or stdout/logs:
    /// - Bearer token is read ONLY from `--bearer-token-env` (default `R5E_TOKEN`) or `--bearer-token-file`.
    /// - Releaser signing key is read from `--releaser-key-file` (`0600`) or `--releaser-seed-env`.
    ReleaseHold {
        #[arg(long)]
        gateway_url: String,
        /// Evidence reference (`evidence:sha256:...`) of the `RetentionHold` to release.
        #[arg(long, visible_alias = "hold-ref")]
        hold: String,
        /// Non-empty human-readable reason recorded in `RetentionHoldRelease.body.reason`.
        #[arg(long)]
        reason: String,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Counsel / releaser Ed25519 private signing key file (`0600` raw seed, base64 seed, or PKCS#8 PEM).
        #[arg(
            long = "releaser-key-file",
            visible_aliases = ["releaser-seed-file", "signer-key-file", "key-file", "counsel-key-file"]
        )]
        releaser_key_file: Option<PathBuf>,
        /// Fallback environment variable holding base64/PEM releaser signing key when `--releaser-key-file` is omitted.
        #[arg(long, default_value = "R5E_RELEASER_SEED_B64")]
        releaser_seed_env: String,
        /// Optional `{records, keys, blobs}` grant set JSON file produced by `grant-releaser`.
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
        /// Optional path to write the canonical hold-release receipt JSON.
        #[arg(long = "out-receipt-file", visible_alias = "out-receipt")]
        out_receipt_file: Option<PathBuf>,
    },
    /// Enrol an ephemeral workload `Badge` (`POST /v1/authority/badges/{prepare,finalize}`, `A8` §2.3),
    /// mirror the gateway's `CaptureProfile.retention` verbatim into the workload's local
    /// `r5e.capture-profile/v2` blob, persist the `0600` enrolled state + signing seed to
    /// `--out-state`, and print a zero-secret JSON summary.
    EnrolBadge {
        #[arg(long)]
        gateway_url: String,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Badge `holder` slug (lowercase alphanumeric + hyphens).
        #[arg(long, default_value = "endpoint-helper")]
        holder: String,
        /// Optional stable workload URI identity (`Badge.body.workload`, e.g. `urn:r5e:workload:codex`).
        #[arg(long)]
        workload: Option<String>,
        /// Optional human-readable purpose for this badge enrolment.
        #[arg(long)]
        purpose: Option<String>,
        /// Optional requested badge TTL in seconds (`requestedTtlSeconds`).
        #[arg(long = "ttl-seconds", visible_alias = "requested-ttl-seconds")]
        ttl_seconds: Option<u64>,
        /// Repeatable requested actor prefix (`requestedActorPrefixes`).
        #[arg(
            long = "actor-prefix",
            visible_alias = "actor-prefixes",
            value_delimiter = ','
        )]
        actor_prefixes: Vec<String>,
        /// Repeatable requested operational kind (defaults to `SessionOpened`, `SessionClosed`,
        /// `PolicyDecision`, `ToolCall`, `ToolResult`, `Observation`, `Disclosure`, `Verification`).
        #[arg(long = "kind", visible_alias = "kinds", value_delimiter = ',')]
        kinds: Vec<String>,
        /// Optional local Cedar policy file whose content is hashed as `deploymentPolicyRef`
        /// and stored in `state` blobs (`text/plain`).
        #[arg(long = "cedar-policy", visible_alias = "policy-file")]
        cedar_policy: Option<PathBuf>,
        /// Require inline `body.policy` (`VERIFY-V2` §6.3 `policyRequiredKinds`) on every
        /// `provenance.r5e.io/v2/ToolCall` recorded under this badge's local `CaptureProfile`.
        #[arg(long, default_value_t = false)]
        require_policy_for_tools: bool,
        /// Repeatable kind requiring inline `body.policy` in the local `CaptureProfile` (default `[]`).
        #[arg(long = "policy-required-kind", value_delimiter = ',')]
        policy_required_kinds: Vec<String>,
        /// Output path (`0600` permissions on Unix) for the enrolled state + workload Ed25519 signing seed.
        #[arg(long = "out-state", visible_alias = "state")]
        out_state: PathBuf,
        /// Allow overwriting an existing `--out-state` file.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Open an anchored workload session on the gateway (`POST /v1/evidence/sessions`, `A8` §3.1),
    /// printing `{"session", "already_open", "ref"?, "seq"?}` and optionally binding `session_urn` in `--state`.
    OpenSession {
        /// Gateway base URL (`http://127.0.0.1:4000`). Defaults to `--state`'s `gateway_url` when omitted.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Optional raw client session identifier (`1..=128` UTF-8 bytes, sent raw as `clientSessionId`).
        #[arg(long = "client-session-id", visible_alias = "session-id")]
        client_session_id: Option<String>,
        /// Optional human-readable purpose (`SessionOpened.body.details.purpose`).
        #[arg(long)]
        purpose: Option<String>,
        /// Optional stable workload URI (`SessionOpened.body.details.workload`).
        #[arg(long)]
        workload: Option<String>,
        /// Optional JSON object merged into `OpenSessionRequest.details`.
        #[arg(long)]
        details_json: Option<String>,
        /// Optional `0600` enrolled state file whose bound `session_urn` should be updated in-place.
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Ship workload operational records from an exported `r5e.provenance-export/v2` bundle
    /// (`--bundle-dir` / `--bundle`) or saved `0600` enrolled `--state` file to
    /// `POST /v1/evidence/records` (`A8` §2), auto-chunking into `<= 64`-record batches.
    ShipBundle {
        /// Gateway base URL (`http://127.0.0.1:4000`). Defaults to `--state`'s `gateway_url` when omitted.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Path to an exported Provenance v2 directory (containing `bundle.json` / `export.json`)
        /// or a bundle JSON file.
        #[arg(
            long = "bundle-dir",
            visible_aliases = ["bundle", "bundle-file"]
        )]
        bundle_dir: Option<PathBuf>,
        /// Path to a `0600` enrolled state file created by `enrol-badge`.
        #[arg(long)]
        state: Option<PathBuf>,
        /// When shipping from `--state`, skip records already recorded in `shipped_record_refs`.
        #[arg(long, default_value_t = false)]
        only_unshipped: bool,
        /// Omit inline content/payload blobs while still carrying `CaptureProfile` (`A8` §4.3
        /// missing-content tolerance).
        #[arg(long, default_value_t = false)]
        omit_payload_blobs: bool,
        /// Optional `{records, keys, blobs}` offline authority JSON file (`ShipRecordsRequest.authority`).
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
    },
    /// Append a signed workload operational record (`PolicyDecision`, `ToolCall`, `ToolResult`,
    /// `Observation`, `SessionOpened`, `SessionClosed`, `Disclosure`, `Verification`) onto the
    /// badge's stream in `--state` (`0600`), and optionally `--ship` unshipped records to
    /// `POST /v1/evidence/records` (`A8` §§2–4).
    #[command(visible_aliases = ["record-and-ship", "record-tool-call", "record"])]
    RecordEvent {
        /// Path to the `0600` enrolled state file created by `enrol-badge`.
        #[arg(long)]
        state: PathBuf,
        /// Operational kind (`ToolCall`, `ToolResult`, `PolicyDecision`, `Observation`,
        /// `SessionOpened`, `SessionClosed`, `Disclosure`, `Verification`, or full `<pkg>/v2/<Kind>`).
        #[arg(long, default_value = "ToolCall")]
        kind: String,
        /// Stream suffix appended to `<stream_prefix>` (e.g. `events` -> `urn:r5e:stream:<dep>:workload:<hex>:events`).
        #[arg(long, default_value = "events")]
        stream_suffix: String,
        /// Optional session URN override (`evidence.session`); defaults to `state.session_urn` unless `--no-session`.
        #[arg(long)]
        session: Option<String>,
        /// Explicitly omit `evidence.session` even if `state.session_urn` is set.
        #[arg(long, default_value_t = false)]
        no_session: bool,
        /// Optional `evidence.actor` URI; defaults to `state.default_actor()`.
        #[arg(long)]
        actor: Option<String>,
        /// Optional explicit RFC 3339 `capturedAt` timestamp; defaults to `Utc::now()` (micros).
        #[arg(long)]
        captured_at: Option<String>,
        /// Tool name for `ToolCall` (`body.tool`).
        #[arg(long = "tool-name", visible_alias = "tool")]
        tool_name: Option<String>,
        /// Input payload file hashed into `state` blobs (`bytes:sha256:...`).
        #[arg(long)]
        input_file: Option<PathBuf>,
        /// Inline UTF-8 input payload text hashed into `state` blobs (`bytes:sha256:...`).
        #[arg(long)]
        input_text: Option<String>,
        /// Output payload file hashed into `state` blobs (`bytes:sha256:...`).
        #[arg(long)]
        output_file: Option<PathBuf>,
        /// Inline UTF-8 output payload text hashed into `state` blobs (`bytes:sha256:...`).
        #[arg(long)]
        output_text: Option<String>,
        /// Media type recorded for `--input-file` / `--output-file` blobs.
        #[arg(long, default_value = "application/json")]
        media_type: String,
        /// Required prior `ToolCall` evidence reference (`ToolResult.body.call`, `A9` §2).
        #[arg(long)]
        call_ref: Option<String>,
        /// Optional top-level `callId` (`ToolCall.body.callId` / `ToolResult.body.callId`, `1..=256` UTF-8 bytes, `A9` §2).
        #[arg(long = "call-id")]
        call_id: Option<String>,
        /// Optional subject reference (`PolicyDecision.body.subject` or `Verification.body.targetRefs`).
        #[arg(long)]
        subject_ref: Option<String>,
        /// Optional policy reference (`PolicyDecision.body.evaluation.policyRef`); defaults to `state.deployment_policy_ref`.
        #[arg(long)]
        policy_ref: Option<String>,
        /// Outcome enum (`completed` / `allow` / `provided` / `valid` depending on `--kind`).
        #[arg(long)]
        outcome: Option<String>,
        /// Optional non-empty human-readable reason (`body.reason` or `evaluation.reason`).
        #[arg(long)]
        reason: Option<String>,
        /// Observation topic (`Observation.body.topic`).
        #[arg(long)]
        topic: Option<String>,
        /// Optional short summary (`ToolCall` / `ToolResult` `body.summary`).
        #[arg(long)]
        summary: Option<String>,
        /// Recipient URI (`Disclosure.body.recipient`).
        #[arg(long)]
        recipient: Option<String>,
        /// Optional direct JSON string overriding the generated `body` object.
        #[arg(long)]
        body_json: Option<String>,
        /// Optional JSON file overriding the generated `body` object.
        #[arg(long)]
        body_file: Option<PathBuf>,
        /// Optional path to also export a self-contained `r5e.provenance-export/v2` bundle JSON file.
        #[arg(long)]
        out_bundle: Option<PathBuf>,
        /// Immediately ship all unshipped workload records in `--state` to `POST /v1/evidence/records`
        /// (always enabled when invoked as `record-and-ship`).
        #[arg(long, visible_alias = "send", default_value_t = false)]
        ship: bool,
        /// Gateway base URL for `--ship` (`http://127.0.0.1:4000`). Defaults to `state.gateway_url`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Omit inline content/payload blobs while still carrying `CaptureProfile` (`A8` §4.3).
        #[arg(long, default_value_t = false)]
        omit_payload_blobs: bool,
        /// Optional `{records, keys, blobs}` offline authority JSON file (`ShipRecordsRequest.authority`).
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
    },
    /// Revoke an enrolled workload `Badge` on the gateway (`POST /v1/authority/badges/revoke`, `A8` §4.6).
    RevokeBadge {
        /// Gateway base URL (`http://127.0.0.1:4000`). Defaults to `--state`'s `gateway_url` when omitted.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Target `Badge` evidence reference (`evidence:sha256:...`). Defaults to `--state`'s `badge_ref`.
        #[arg(long, visible_alias = "badge-ref")]
        badge: Option<String>,
        /// Optional `0600` enrolled state file providing `badge_ref` (and default `gateway_url`).
        #[arg(long)]
        state: Option<PathBuf>,
        /// Non-empty human-readable revocation reason (`body.reason`).
        #[arg(long)]
        reason: String,
    },
    /// Cedar-gated subprocess wrapper (`LocalCedarGate` + Provenance v2 `PolicyDecision` /
    /// `ToolCall` / `ToolResult` signing, optional `0600` `--outbox` spooling, and `--ship`).
    Exec {
        /// Path to the `0600` enrolled state file created by `enrol-badge`.
        #[arg(long)]
        state: PathBuf,
        /// Local Cedar policy bundle file (defaults to the Cedar policy stored in `--state` when omitted).
        #[arg(long = "cedar-policy", visible_alias = "policy-file")]
        cedar_policy: Option<PathBuf>,
        /// Enforcement posture (`enforce` blocks withheld commands with exit `77`; `observe` runs and records `ObservedWouldWithhold`).
        #[arg(long, value_enum, default_value_t = CliPosture::Enforce)]
        posture: CliPosture,
        /// Optional Cedar `Recurse::Agent` principal ID (defaults to `state.holder`).
        #[arg(long)]
        agent_id: Option<String>,
        /// Optional session URN (`evidence.session`; defaults to `state.session_urn`).
        #[arg(long)]
        session: Option<String>,
        /// Optional `evidence.actor` URI (defaults to `state.default_actor()`).
        #[arg(long)]
        actor: Option<String>,
        /// Stream suffix appended to `state.stream_prefix` (default `"events"`).
        #[arg(long, default_value = "events")]
        stream_suffix: String,
        /// Mark Cedar gate evaluation as explicitly offline (`offlineMode: true`).
        #[arg(long, default_value_t = false)]
        offline: bool,
        /// Optional `0700` offline outbox directory (`0600` queue file) for durable spooling when the gateway is unreachable.
        #[arg(long)]
        outbox: Option<PathBuf>,
        /// Optional `0600` 32-byte symmetric key file for authenticated at-rest outbox encryption (`ChaCha20-Poly1305`; falls back to `R5E_OUTBOX_KEY_FILE`).
        #[arg(long)]
        outbox_key_file: Option<PathBuf>,
        /// Immediately ship signed records + blobs to `POST /v1/evidence/records` (if shipping fails and `--outbox` is set, keeps them queued!).
        #[arg(long, visible_alias = "send", default_value_t = false)]
        ship: bool,
        /// Gateway base URL (`http://127.0.0.1:4000`). Defaults to `state.gateway_url`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Optional `{records, keys, blobs}` offline authority JSON file (`ShipRecordsRequest.authority`).
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
        /// Optional top-level `callId` (`ToolCall.body.callId` & `ToolResult.body.callId`, `1..=256` UTF-8 bytes; defaults to generated `exec-<16hex>`).
        #[arg(long = "call-id")]
        call_id: Option<String>,
        /// Optional path to export a self-contained `r5e.provenance-export/v2` bundle JSON file after execution.
        #[arg(long)]
        out_bundle: Option<PathBuf>,
        /// Target command and arguments (`-- <PROGRAM> [ARGS...]`).
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Live `stdio` JSON-RPC 2.0 MCP tool-server proxy with canonical `tools/list` pinning,
    /// rug-pull quarantine (`--block-rug-pull`), Cedar `tools/call` gating, and Provenance v2 signing/shipping.
    McpProxy {
        /// Logical MCP server identifier (`Recurse::McpTool::"<server_id>:<tool_name>"`).
        #[arg(long)]
        server_id: String,
        /// Path to the `0600` enrolled state file created by `enrol-badge`.
        #[arg(long)]
        state: PathBuf,
        /// Local Cedar policy bundle file (defaults to the Cedar policy stored in `--state` when omitted).
        #[arg(long = "cedar-policy", visible_alias = "policy-file")]
        cedar_policy: Option<PathBuf>,
        /// Enforcement posture (`enforce` or `observe`).
        #[arg(long, value_enum, default_value_t = CliPosture::Enforce)]
        posture: CliPosture,
        /// Latch quarantine on mid-session `tools/list` descriptor mutation and intercept all subsequent `tools/call` frames.
        #[arg(long, default_value_t = false)]
        block_rug_pull: bool,
        /// Optional Cedar `Recurse::Agent` principal ID (defaults to `state.holder`).
        #[arg(long)]
        agent_id: Option<String>,
        /// Optional session URN (`evidence.session`; defaults to `state.session_urn`).
        #[arg(long)]
        session: Option<String>,
        /// Optional `evidence.actor` URI (defaults to `state.default_actor()`).
        #[arg(long)]
        actor: Option<String>,
        /// Stream suffix appended to `state.stream_prefix` (default `"events"`).
        #[arg(long, default_value = "events")]
        stream_suffix: String,
        /// Mark Cedar gate evaluation as explicitly offline (`offlineMode: true`).
        #[arg(long, default_value_t = false)]
        offline: bool,
        /// Optional `0700` offline outbox directory (`0600` queue file) for durable spooling when the gateway is unreachable.
        #[arg(long)]
        outbox: Option<PathBuf>,
        /// Optional `0600` 32-byte symmetric key file for authenticated at-rest outbox encryption (`ChaCha20-Poly1305`; falls back to `R5E_OUTBOX_KEY_FILE`).
        #[arg(long)]
        outbox_key_file: Option<PathBuf>,
        /// Immediately ship signed records + blobs to `POST /v1/evidence/records` after each mediated exchange.
        #[arg(long, visible_alias = "send", default_value_t = false)]
        ship: bool,
        /// Gateway base URL (`http://127.0.0.1:4000`). Defaults to `state.gateway_url`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Optional `{records, keys, blobs}` offline authority JSON file (`ShipRecordsRequest.authority`).
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
        /// Optional path to export a self-contained `r5e.provenance-export/v2` bundle JSON file when the session ends.
        #[arg(long)]
        out_bundle: Option<PathBuf>,
        /// Child MCP server command and arguments (`-- <MCP_SERVER_CMD> [ARGS...]`).
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Ship pending signed workload records and blobs queued in an offline `0600` `--outbox`
    /// directory to `POST /v1/evidence/records`, removing entries once `admitted` / `already_admitted`.
    FlushOutbox {
        /// Path to the `0700` outbox directory containing `outbox-queue.json` (`0600`).
        #[arg(long)]
        outbox: PathBuf,
        /// Optional gateway base URL override (`http://127.0.0.1:4000`); defaults to the outbox queue's or `--state`'s `gateway_url`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Optional `0600` enrolled state file whose `shipped_record_refs` should also be updated on flush.
        #[arg(long)]
        state: Option<PathBuf>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Optional `{records, keys, blobs}` offline authority JSON file (`ShipRecordsRequest.authority`).
        #[arg(long = "authority-file", visible_alias = "grant-file")]
        authority_file: Option<PathBuf>,
        /// Optional `0600` 32-byte symmetric key file for authenticated at-rest outbox decryption (`ChaCha20-Poly1305`; falls back to `R5E_OUTBOX_KEY_FILE`).
        #[arg(long)]
        outbox_key_file: Option<PathBuf>,
    },
    /// Native Rust agent lifecycle hook handler (`antigravity`, `claude-code`, or `codex`).
    /// Reads hook JSON on stdin, redacts secrets, optionally evaluates Cedar in `enforce` mode,
    /// enqueues locally (`0600`), and spawns a detached background drainer (`File::try_lock`) so
    /// stdin -> stdout completes in <20 ms.
    Hook {
        /// Agent client format (`antigravity`, `claude-code`, or `codex`).
        #[arg(value_enum)]
        client: CliHookClient,
        /// Hook mode (`observe` is strictly fail-open; `enforce` gates `PreToolUse` via Cedar).
        #[arg(long, value_enum, default_value_t = CliHookMode::Observe)]
        mode: CliHookMode,
        /// Gateway base URL (`https://...` or `http://127.0.0.1:4000`; falls back to `R5E_GATEWAY_URL`).
        #[arg(long = "gateway", visible_alias = "gateway-url")]
        gateway: Option<String>,
        /// Directory holding `0700`/`0600` per-conversation hook queues, enrolled states, and logs.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Environment variable holding the gateway bearer token (never pass raw tokens on CLI argv).
        #[arg(
            long = "bearer-token-env",
            visible_alias = "token-env",
            default_value = "R5E_TOKEN"
        )]
        bearer_token_env: String,
        /// Optional file (`0600` recommended) containing the gateway bearer token.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
        /// Optional local Cedar policy bundle file (used in `enforce` mode and badge enrolment).
        #[arg(long = "cedar-policy", visible_alias = "policy-file")]
        cedar_policy: Option<PathBuf>,
        /// Internal detached background drainer target conversation ID.
        #[arg(long, hide = true)]
        drain: Option<String>,
    },
    /// Write or merge native `r5e-endpoint-helper hook` configuration for `antigravity`,
    /// `claude-code`, or `codex` without clobbering existing user hooks.
    InstallHooks {
        /// Agent client to configure (`antigravity`, `claude-code`, or `codex`).
        #[arg(value_enum)]
        client: CliHookClient,
        /// Gateway base URL (`https://...` or `http://127.0.0.1:4000`).
        #[arg(
            long = "gateway",
            visible_alias = "gateway-url",
            default_value = "http://127.0.0.1:4000"
        )]
        gateway: String,
        /// Hook mode (`observe` or `enforce`).
        #[arg(long, value_enum, default_value_t = CliHookMode::Observe)]
        mode: CliHookMode,
        /// Target configuration directory (e.g. `.agents` for Antigravity, `~/.claude` for Claude Code).
        #[arg(long)]
        path: PathBuf,
        /// Optional hook state directory passed through to `hook --state-dir`.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Optional local Cedar policy file passed through to `hook --cedar-policy`.
        #[arg(long = "cedar-policy", visible_alias = "policy-file")]
        cedar_policy: Option<PathBuf>,
        /// Optional bearer token file passed through to `hook --bearer-token-file`.
        #[arg(long = "bearer-token-file", visible_alias = "token-file")]
        bearer_token_file: Option<PathBuf>,
    },
    /// Print a machine-readable endpoint hook/enrollment status snapshot for desktop/tray IPC.
    Status {
        /// Hook state directory to inspect (defaults to `R5E_HOOK_STATE_DIR` or `~/.config/r5e/hooks`).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Emit canonical machine-readable JSON (`version`, `gateway_url`, `enrolled`, `badge_ref`, `active_sessions`, `queued_events`, `last_ship_at`, `last_error`).
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Generate a fresh `0600` 32-byte OS-random symmetric key file for authenticated at-rest
    /// outbox encryption (`--outbox-key-file` / `R5E_OUTBOX_KEY_FILE`).
    GenerateOutboxKey {
        /// Output path for the `0600` 32-byte symmetric key file.
        #[arg(long, visible_alias = "out-key-file")]
        out: PathBuf,
        /// Allow overwriting an existing key file atomically (`0600`).
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Offline root workload badge ceremony: mints a Provenance v2 `[Endorsement..., Badge]`
    /// authority chain (`SubmitGrantsRequest`) granting a workload key bounded operational standing
    /// on `urn:r5e:stream:<deployment>:endpoint:offline-<24hex>:` ready for `POST /v1/deployment/grants`.
    ///
    /// Multiple `--root-key-file` arguments form a sequential endorsement chain (`R_1 -> ... -> R_m -> W`),
    /// NOT a k-of-n threshold signature; with a single `--root-key-file`, uses `--delegator-key-file`
    /// or a zeroized ephemeral ceremony delegator key so `E_0` is never a self-endorsement (`A5` §4.7).
    #[command(visible_alias = "mint-offline-badge")]
    MintWorkloadBadge {
        /// Offline deployment root Ed25519 private key file(s) (repeatable: sequential chain `R_1 -> ... -> R_m`).
        #[arg(long = "root-key-file", required = true)]
        root_key_files: Vec<PathBuf>,
        /// Optional intermediate delegator Ed25519 private key file when a single `--root-key-file` is given.
        #[arg(long)]
        delegator_key_file: Option<PathBuf>,
        /// Workload Ed25519 private key file for 1-step co-signing (`Signature #2` on `Badge`).
        #[arg(long)]
        workload_key_file: Option<PathBuf>,
        /// Generate a fresh `0600` workload Ed25519 private key file and co-sign in 1 step.
        #[arg(long)]
        generate_workload_key_out: Option<PathBuf>,
        /// Air-gapped 2-step mode: workload public key (SPKI PEM/DER, JSON, base64, or hex for `ed25519`, `es256`, or `es384`) to prepare a draft for `cosign-workload-badge`.
        #[arg(long)]
        workload_public_key: Option<String>,
        /// Optional signature algorithm for `--workload-public-key` (`ed25519`, `es256`, or `es384`; inferred from SPKI PEM/JSON or key length when omitted).
        #[arg(long = "workload-algorithm")]
        workload_algorithm: Option<String>,
        /// Deployment slug (`acme-prod`) or stream prefix (`urn:r5e:stream:acme-prod:`); auto-discovered if `--gateway-url` is provided.
        #[arg(long, visible_alias = "stream-prefix")]
        deployment: Option<String>,
        /// Optional gateway base URL (`http://127.0.0.1:4000`) for `GET /v1/deployment` discovery, `--out-state`, or `--submit`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Optional gateway key ID (`key:ed25519:sha256:...`) for authority profile `sealerKeys`.
        #[arg(long)]
        gateway_key_id: Option<String>,
        /// Required principal URI (`actsFor` on every `Endorsement` and `Badge`).
        #[arg(long, visible_alias = "acts-for")]
        principal: String,
        /// Required workload URI (`Badge.body.workload` and `actorPrefixes[0]`).
        #[arg(long)]
        workload: String,
        /// Optional additional `actorPrefixes` URI(s) beyond `--workload` (repeatable).
        #[arg(long = "actor-prefix")]
        actor_prefixes: Vec<String>,
        /// Badge `holder` slug (`^[a-z][a-z0-9-]*$`).
        #[arg(long, default_value = "endpoint-helper")]
        holder: String,
        /// Optional human-readable purpose recorded in local `--out-state` (`EnrolledStateFile`).
        #[arg(long)]
        purpose: Option<String>,
        /// Permitted operational workload kind(s) (repeatable; defaults to the 8 standard workload kinds).
        #[arg(long = "permitted-kind", visible_alias = "kind")]
        permitted_kinds: Vec<String>,
        /// Optional local Cedar policy file embedded into `--out-state` (`EnrolledStateFile`).
        #[arg(long = "policy-file", visible_alias = "cedar-policy")]
        policy_file: Option<PathBuf>,
        /// Kind(s) requiring a `PolicyDecision` in the workload's local `CaptureProfile` (`--out-state`).
        #[arg(long = "policy-required-kind")]
        policy_required_kinds: Vec<String>,
        /// Include `provenance.r5e.io/v2/ToolCall` in `policyRequiredKinds` when writing `--out-state` (default `true`).
        #[arg(
            long,
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        require_policy_for_tools: bool,
        /// Optional retention disposal mode (`never` or `by-record`) for `--out-state` `CaptureProfile` parity.
        #[arg(long)]
        retention_disposal: Option<String>,
        /// Retention duration in seconds when `--retention-disposal by-record` is used for `--out-state`.
        #[arg(long)]
        keep_content_for_seconds: Option<u64>,
        /// Explicit RFC 3339 `notBefore` timestamp (must be `<= capturedAt`).
        #[arg(long)]
        not_before: Option<String>,
        /// Explicit RFC 3339 `notAfter` expiration timestamp (`<= notBefore + 43200s`).
        #[arg(long, visible_alias = "not-after")]
        expires_at: Option<String>,
        /// Validity window in seconds when `--expires-at` is omitted (default `3600`, max `43200`).
        #[arg(long)]
        ttl_seconds: Option<u64>,
        /// Leaf workload badges cannot endorse further keys; must remain `false` (`A5` §4.3).
        #[arg(
            long,
            default_value_t = false,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        may_endorse: bool,
        /// Envelope `actor` URI on offline authority records.
        #[arg(long, default_value = "urn:r5e:operator:root")]
        operator_actor: String,
        /// Optional 24-character lowercase hex token for `offline-<24hex>` stream naming.
        #[arg(long)]
        badge_token: Option<String>,
        /// Write the completed `{records, keys, blobs}` `SubmitGrantsRequest` JSON to this path.
        #[arg(long, visible_alias = "out")]
        out_grant_file: Option<PathBuf>,
        /// Write the zero-secret `PreparedOfflineWorkloadBadge` JSON for 2-step `cosign-workload-badge`.
        #[arg(long)]
        out_prepared_badge: Option<PathBuf>,
        /// Optional path to write the exact raw DSSE PAE bytes for hardware/external Signer #2 (PIV / `openssl` / PKCS#11).
        #[arg(long = "out-badge-pae")]
        out_badge_pae: Option<PathBuf>,
        /// Optional `0600` `EnrolledStateFile` output path (requires 1-step workload signing key).
        #[arg(long)]
        out_state: Option<PathBuf>,
        /// Submit the completed grant set immediately to `POST <gateway_url>/v1/deployment/grants`.
        #[arg(long, default_value_t = false)]
        submit: bool,
        /// Allow overwriting existing `--out-state` / `--generate-workload-key-out` files.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Air-gapped Step 2: verify a `PreparedOfflineWorkloadBadge` draft (`--prepared-badge`),
    /// attach `Signature #2` using `--workload-key-file` OR a detached external/PIV signature
    /// (`--signature-file` / `--signature-b64`, auto-normalizing ASN.1 DER + high-`S`), and emit `--out-grant-file` / `--out-state`.
    CosignWorkloadBadge {
        /// Path to the `PreparedOfflineWorkloadBadge` JSON created by `mint-workload-badge --workload-public-key`.
        #[arg(long)]
        prepared_badge: PathBuf,
        /// Workload Ed25519 private key file matching `prepared.workload_key_id` (mutually exclusive with `--signature-file` / `--signature-b64`).
        #[arg(long)]
        workload_key_file: Option<PathBuf>,
        /// Detached external signature file (raw `r || s`, ASN.1 DER `ECDSA-Sig-Value`, 64B Ed25519, base64, or hex).
        #[arg(long = "signature-file")]
        signature_file: Option<PathBuf>,
        /// Detached external signature as base64 (raw `r || s`, ASN.1 DER `ECDSA-Sig-Value`, or 64B Ed25519).
        #[arg(long = "signature-b64", visible_alias = "signature")]
        signature_b64: Option<String>,
        /// Write the completed `{records, keys, blobs}` `SubmitGrantsRequest` JSON to this path.
        #[arg(long, visible_alias = "out")]
        out_grant_file: Option<PathBuf>,
        /// Optional `0600` `EnrolledStateFile` output path.
        #[arg(long)]
        out_state: Option<PathBuf>,
        /// Optional gateway base URL (`http://127.0.0.1:4000`) for `--out-state` or `--submit`.
        #[arg(long)]
        gateway_url: Option<String>,
        /// Optional local Cedar policy file embedded into `--out-state`.
        #[arg(long = "policy-file", visible_alias = "cedar-policy")]
        policy_file: Option<PathBuf>,
        /// Kind(s) requiring a `PolicyDecision` in the workload's local `CaptureProfile` (`--out-state`).
        #[arg(long = "policy-required-kind")]
        policy_required_kinds: Vec<String>,
        /// Include `provenance.r5e.io/v2/ToolCall` in `policyRequiredKinds` when writing `--out-state` (default `true`).
        #[arg(
            long,
            default_value_t = true,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        require_policy_for_tools: bool,
        /// Optional retention disposal mode (`never` or `by-record`) for `--out-state`.
        #[arg(long)]
        retention_disposal: Option<String>,
        /// Retention duration in seconds when `--retention-disposal by-record` is used for `--out-state`.
        #[arg(long)]
        keep_content_for_seconds: Option<u64>,
        /// Submit the completed grant set immediately to `POST <gateway_url>/v1/deployment/grants`.
        #[arg(long, default_value_t = false)]
        submit: bool,
        /// Allow overwriting an existing `--out-state` file.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Submit a `{records, keys, blobs}` authority grant JSON file (`mint-workload-badge`,
    /// `cosign-workload-badge`, `grant-gateway`, or `grant-releaser`) to `POST /v1/deployment/grants`.
    #[command(visible_alias = "submit-grants")]
    SubmitGrant {
        /// Gateway base URL (`http://127.0.0.1:4000`).
        #[arg(long)]
        gateway_url: String,
        /// Path to the `{records, keys, blobs}` `SubmitGrantsRequest` JSON file.
        #[arg(long, visible_alias = "authority-file")]
        grant_file: PathBuf,
    },
    /// Detached external-signer Step 1 (`BLOCK-0.md` & `A9` §6): assemble an unsigned
    /// `provenance.r5e.io/v2/DefinitionPublished` payload, its publisher `CaptureProfile` blob,
    /// and all expanded definition blobs (`index.json` or `.json`), writing `--out-prepared` and
    /// the exact raw DSSE PAE bytes (`--out-pae`) to sign externally with `ykman` / `openssl` / PKCS#11 / HSM.
    PreparePublication {
        /// Directory containing `index.json` + `<kind>.json` or expanded `r5e.kind-definition/v1` `.json` files
        /// (defaults to `$R5E_DEFINITIONS_DIR` or `./definitions`).
        #[arg(long = "definitions-dir")]
        definitions_dir: Option<PathBuf>,
        /// Publisher public key (SPKI PEM/DER file, `{algorithm, bytes}` JSON file, or inline base64 / hex).
        #[arg(long = "publisher-public-key", visible_alias = "public-key")]
        publisher_public_key: String,
        /// Signature algorithm (`ed25519`, `es256`, or `es384`; inferred from SPKI PEM/JSON when omitted).
        #[arg(long = "algorithm", visible_alias = "alg")]
        algorithm: Option<String>,
        /// Short publisher name used in default `actor` and `stream` (default `"r5e"`).
        #[arg(long, default_value = "r5e")]
        name: String,
        /// Optional package name (`DefinitionPublished.body.package`, e.g. `"r5e.provenance"`).
        #[arg(long)]
        package: Option<String>,
        /// Optional accepted proposal ref (`evidence:sha256:<64hex>` or `chain:evidence:sha256:<64hex>/evidence:sha256:<64hex>`, `A9` §§5–6).
        #[arg(long)]
        proposal: Option<String>,
        /// Optional superseded publication record ref (`DefinitionPublished.body.previous`, `evidence:sha256:<64hex>`).
        #[arg(long)]
        previous: Option<String>,
        /// Optional stream `seq` override (default `1`; when `> 1`, requires `--previous`).
        #[arg(long)]
        seq: Option<u64>,
        /// Optional authored package manifest ref (`DefinitionPublished.body.manifestRef`, `bytes:sha256:<64hex>`).
        #[arg(long = "manifest-ref")]
        manifest_ref: Option<String>,
        /// Optional explicit publication stream URI (defaults to `urn:r5e:stream:publisher:<name>:api:<16hex>`).
        #[arg(long)]
        stream: Option<String>,
        /// Optional explicit publisher `actor` URI (defaults to `urn:r5e:publisher:<name>`).
        #[arg(long)]
        actor: Option<String>,
        /// Optional RFC 3339 `capturedAt` timestamp (defaults to current UTC time in microseconds).
        #[arg(long = "captured-at")]
        captured_at: Option<String>,
        /// Optional flat A9 `Details` JSON object (`<= 64` scalar entries).
        #[arg(long = "details-json")]
        details_json: Option<String>,
        /// Enforce the PIV hardware `Ed25519` 3,000-byte PAE ceiling.
        #[arg(long = "piv-hardware", default_value_t = false)]
        piv_hardware: bool,
        /// Output path for the unsigned `PreparedPublication` JSON file.
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        /// Output path for the exact raw DSSE PAE bytes to sign externally on hardware (`ykman` / `openssl` / PKCS#11).
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached external-signer Step 2 (`BLOCK-0.md` & `VERIFY-V2` §2.3): attach an external
    /// `ed25519` / `es256` / `es384` signature (`--signature-file` or `--signature-b64`, auto-normalizing
    /// ASN.1 DER `ECDSA-Sig-Value` and `s > floor(n / 2)` -> `n - s`), cryptographically verify over
    /// the DSSE PAE and all definition blobs BEFORE atomically writing `--out <publications.json>`.
    FinalizePublication {
        /// Path to the `PreparedPublication` JSON file written by `prepare-publication`.
        #[arg(long)]
        prepared: PathBuf,
        /// Path to the detached signature file (raw `r || s`, binary ASN.1 DER `ECDSA-Sig-Value`, 64B Ed25519, base64, or hex).
        #[arg(long = "signature-file")]
        signature_file: Option<PathBuf>,
        /// Base64-encoded detached signature (raw `r || s`, ASN.1 DER `ECDSA-Sig-Value`, or 64B Ed25519).
        #[arg(long = "signature-b64", visible_alias = "signature")]
        signature_b64: Option<String>,
        /// Output path for the finalized `publications.json` (`R5E_EVIDENCE_PUBLICATIONS_FILE`).
        #[arg(long, visible_alias = "out-publications")]
        out: PathBuf,
        /// Write `--out` with `0600` owner-only permissions instead of `0644`.
        #[arg(long, default_value_t = false)]
        mode_0600: bool,
    },
    /// Detached hardware-root Step 1 (`BLOCK-0.md` & `A6`): `POST /v1/deployment/claim/prepare`
    /// using an `ed25519 | es256 | es384` root public key (`ykman piv keys export 9c`, SPKI PEM,
    /// SEC1, or JSON), verify all chain/publication/terms invariants offline BEFORE any hardware
    /// signature is requested, and write zero-secret `--out-prepared` + raw DSSE PAE `--out-pae`.
    PrepareClaim {
        #[arg(long)]
        gateway_url: String,
        #[arg(long)]
        claim_code_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_CLAIM_CODE")]
        claim_code_env: String,
        /// Claiming root public key (SPKI PEM/DER from `ykman piv keys export`, `{algorithm, bytes}` JSON, SEC1, base64, or hex).
        #[arg(long = "root-public-key", visible_alias = "public-key")]
        root_public_key: String,
        /// Optional signature algorithm (`ed25519`, `es256`, or `es384`; inferred from SPKI PEM/JSON when omitted).
        #[arg(long = "algorithm", visible_alias = "alg")]
        algorithm: Option<String>,
        #[arg(long)]
        holder: Option<String>,
        #[arg(long)]
        custody: Option<String>,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        roots_file: Option<PathBuf>,
        #[arg(long = "additional-root")]
        additional_roots: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long = "recovery-key")]
        recovery_keys: Vec<String>,
        #[arg(long = "generate-recovery-key")]
        generate_recovery_keys: Vec<PathBuf>,
        #[arg(long = "custodian")]
        custodians: Vec<String>,
        #[arg(long, default_value_t = false)]
        allow_permanent_roots: bool,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long = "trusted-publisher")]
        trusted_publishers: Vec<String>,
        #[arg(long, default_value_t = false)]
        allow_untrusted_publisher: bool,
        /// Allow `ed25519` PAEs larger than PIV's 3,000-byte ceiling (e.g. non-PIV HSM).
        #[arg(long = "allow-large-ed25519-pae", default_value_t = false)]
        allow_large_ed25519_pae: bool,
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached hardware-root Step 2 (`BLOCK-0.md` & `VERIFY-V2` §2.3): attach an external root
    /// signature (`ed25519 | es256 | es384`, auto-normalizing PIV / OpenSSL ASN.1 DER
    /// `ECDSA-Sig-Value` and `s > floor(n / 2)` -> `n - s`), verify over DSSE PAE BEFORE POSTing
    /// to `/v1/deployment/claim/finalize`, and verify the gateway's finalized `Deployment` response.
    FinalizeClaim {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long)]
        gateway_url: Option<String>,
        #[arg(long)]
        claim_code_file: Option<PathBuf>,
        #[arg(long, default_value = "R5E_CLAIM_CODE")]
        claim_code_env: String,
        #[arg(long = "signature-file", visible_alias = "root-signature-file")]
        signature_file: Option<PathBuf>,
        #[arg(
            long = "signature-b64",
            visible_aliases = ["signature", "root-signature-b64"]
        )]
        signature_b64: Option<String>,
        #[arg(long)]
        out_receipt: Option<PathBuf>,
    },
    /// Detached hardware-signer Step 1 (`BLOCK-0.md`): prepare an unsigned
    /// `provenance.r5e.io/v2/Endorsement` record for an `ed25519 | es256 | es384` root/issuer
    /// public key (`ykman piv keys export 9c`), writing `--out-prepared` and raw DSSE PAE `--out-pae`.
    PrepareEndorsement {
        /// Issuer / Root public key (SPKI PEM/DER, `{algorithm, bytes}` JSON, SEC1, base64, or hex).
        #[arg(long = "issuer-public-key", visible_alias = "root-public-key")]
        issuer_public_key: String,
        /// Optional signature algorithm (`ed25519`, `es256`, or `es384`; inferred from SPKI PEM/JSON when omitted).
        #[arg(long = "algorithm", visible_alias = "alg")]
        algorithm: Option<String>,
        /// Subject key ID (`key:<alg>:sha256:<64hex>`). If omitted, derived from `--subject-public-key` or `GET /v1/deployment` (`gatewayKey`).
        #[arg(long = "subject", visible_alias = "gateway-key-id")]
        subject: Option<String>,
        /// Optional subject public key file/string (SPKI PEM/DER/JSON) to derive `--subject`.
        #[arg(long = "subject-public-key")]
        subject_public_key: Option<String>,
        /// Optional gateway URL (`http://127.0.0.1:4000`) to discover `deployment`, `gatewayKey`, and microsecond floor.
        #[arg(long)]
        gateway_url: Option<String>,
        #[arg(long)]
        deployment: Option<String>,
        #[arg(long)]
        stream_prefix: Option<String>,
        /// Optional collision-free sub-stream token (`authority:root:<hex>:grant:<token>`).
        #[arg(long = "grant-token")]
        grant_token: Option<String>,
        #[arg(long, default_value_t = 1)]
        seq: u64,
        #[arg(long)]
        previous: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        #[arg(long = "kind", visible_alias = "kinds", value_delimiter = ',')]
        kinds: Option<Vec<String>>,
        #[arg(
            long = "stream-prefix-grant",
            visible_alias = "stream-prefixes",
            value_delimiter = ','
        )]
        stream_prefixes: Option<Vec<String>>,
        #[arg(
            long = "actor-prefix",
            visible_alias = "actor-prefixes",
            value_delimiter = ','
        )]
        actor_prefixes: Option<Vec<String>>,
        /// Omit `actorPrefixes` on the `Endorsement` (e.g. for `:retention` hold-releaser grants).
        #[arg(long = "omit-actor-prefixes", default_value_t = false)]
        omit_actor_prefixes: bool,
        #[arg(long = "acts-for")]
        acts_for: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        role: Option<String>,
        #[arg(
            long,
            num_args = 0..=1,
            default_value_t = true,
            default_missing_value = "true"
        )]
        may_endorse: bool,
        #[arg(long = "captured-at")]
        captured_at: Option<String>,
        #[arg(long)]
        not_before: Option<String>,
        #[arg(long, default_value_t = 2_592_000)]
        ttl_seconds: u64,
        #[arg(long = "sealer-key", value_delimiter = ',')]
        sealer_keys: Vec<String>,
        #[arg(long = "details-json")]
        details_json: Option<String>,
        #[arg(long = "allow-large-ed25519-pae", default_value_t = false)]
        allow_large_ed25519_pae: bool,
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached hardware-signer Step 2 (`BLOCK-0.md` & `VERIFY-V2` §2.3): attach an external
    /// signature (`ed25519 | es256 | es384`, auto-normalizing ASN.1 DER + high-`S`) onto a
    /// `PreparedEndorsement`, verify over DSSE PAE, write `{records, keys, blobs}` `--out`, and
    /// optionally `--submit` to `POST /v1/deployment/grants`.
    FinalizeEndorsement {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long = "signature-file")]
        signature_file: Option<PathBuf>,
        #[arg(long = "signature-b64", visible_alias = "signature")]
        signature_b64: Option<String>,
        /// Optional companion `{records, keys, blobs}` grant/principal JSON file(s) merged into `--out`.
        #[arg(long = "with-grant-file")]
        with_grant_files: Vec<PathBuf>,
        #[arg(long, visible_alias = "out-grant-file")]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        submit: bool,
        #[arg(long)]
        gateway_url: Option<String>,
    },
    /// Detached hardware-signer Step 1: prepare an unsigned `provenance.r5e.io/v2/Principal`
    /// self-introduction record (`ed25519 | es256 | es384`) on `authority:principal:<hex>`.
    PreparePrincipal {
        #[arg(long = "public-key", visible_alias = "principal-public-key")]
        public_key: String,
        #[arg(long = "algorithm", visible_alias = "alg")]
        algorithm: Option<String>,
        #[arg(long)]
        holder: String,
        #[arg(long)]
        custody: Option<String>,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        gateway_url: Option<String>,
        #[arg(long)]
        deployment: Option<String>,
        #[arg(long)]
        stream_prefix: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:principal")]
        actor: String,
        #[arg(long = "captured-at")]
        captured_at: Option<String>,
        #[arg(long = "sealer-key", value_delimiter = ',')]
        sealer_keys: Vec<String>,
        #[arg(long = "details-json")]
        details_json: Option<String>,
        #[arg(long = "allow-large-ed25519-pae", default_value_t = false)]
        allow_large_ed25519_pae: bool,
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached hardware-signer Step 2: attach an external signature (`ed25519 | es256 | es384`,
    /// auto-normalizing ASN.1 DER + high-`S`) onto a `PreparedPrincipal` and write `{records, keys, blobs}`.
    FinalizePrincipal {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long = "signature-file")]
        signature_file: Option<PathBuf>,
        #[arg(long = "signature-b64", visible_alias = "signature")]
        signature_b64: Option<String>,
        #[arg(long, visible_alias = "out-principal-file")]
        out: PathBuf,
    },
    /// Detached hardware-signer Step 1: prepare an unsigned `provenance.r5e.io/v2/RootsChanged`
    /// proposal (`ed25519 | es256 | es384` signer public key), writing `--out-prepared` + `--out-pae`.
    PrepareRootChange {
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        chain: String,
        #[arg(long)]
        replaces: String,
        #[arg(long)]
        seq: u64,
        #[arg(long, value_enum)]
        authorization: CliAuthorizationMode,
        #[arg(long = "signer-public-key", visible_alias = "public-key")]
        signer_public_key: String,
        #[arg(long = "algorithm", visible_alias = "alg")]
        algorithm: Option<String>,
        #[arg(long = "root-key")]
        root_keys: Vec<String>,
        #[arg(long)]
        roots_file: Option<PathBuf>,
        #[arg(long = "additional-root")]
        additional_roots: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long = "recovery-key")]
        recovery_keys: Vec<String>,
        #[arg(long = "generate-recovery-key")]
        generate_recovery_keys: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long = "custodian")]
        custodians: Vec<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:root")]
        actor: String,
        #[arg(long = "captured-at")]
        captured_at: Option<String>,
        #[arg(long)]
        roots_changed_schema_ref: Option<String>,
        #[arg(long)]
        approval_schema_ref: Option<String>,
        #[arg(long)]
        roots_changed_definition_file: Option<PathBuf>,
        #[arg(long = "allow-large-ed25519-pae", default_value_t = false)]
        allow_large_ed25519_pae: bool,
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached hardware-signer Step 2: attach an external signature (`ed25519 | es256 | es384`,
    /// auto-normalizing ASN.1 DER + high-`S`) onto a `PreparedRootChange` and write `proposal.json`.
    FinalizeRootChange {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long = "signature-file")]
        signature_file: Option<PathBuf>,
        #[arg(long = "signature-b64", visible_alias = "signature")]
        signature_b64: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Detached hardware-signer Step 1: prepare an unsigned 2-signer
    /// `provenance.r5e.io/v2/RootChangeApproval` (`signatures: [root, custodianKey]`, supporting
    /// `ed25519 | es256 | es384` SPKI PEMs), writing `--out-prepared` + `--out-pae`.
    PrepareRootApproval {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long = "root-public-key")]
        root_public_key: String,
        #[arg(long = "root-algorithm")]
        root_algorithm: Option<String>,
        #[arg(long)]
        custodian: String,
        #[arg(long = "custodian-public-key")]
        custodian_public_key: String,
        #[arg(long = "custodian-algorithm")]
        custodian_algorithm: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "urn:r5e:operator:custodian")]
        actor: String,
        #[arg(long = "captured-at")]
        captured_at: Option<String>,
        #[arg(long)]
        approval_schema_ref: Option<String>,
        #[arg(long)]
        approval_definition_file: Option<PathBuf>,
        #[arg(long = "allow-large-ed25519-pae", default_value_t = false)]
        allow_large_ed25519_pae: bool,
        #[arg(long = "out-prepared")]
        out_prepared: PathBuf,
        #[arg(long = "out-pae")]
        out_pae: PathBuf,
    },
    /// Detached hardware-signer Step 2: attach `[root, custodianKey]` external signatures
    /// (`ed25519 | es256 | es384`, auto-normalizing ASN.1 DER + high-`S` on both signers) onto a
    /// `PreparedRootApproval` and append it to `--proposal`.
    FinalizeRootApproval {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long = "root-signature-file")]
        root_signature_file: Option<PathBuf>,
        #[arg(long = "root-signature-b64")]
        root_signature_b64: Option<String>,
        #[arg(long = "custodian-signature-file")]
        custodian_signature_file: Option<PathBuf>,
        #[arg(long = "custodian-signature-b64")]
        custodian_signature_b64: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn parse_pubkey_file_to_key_id(path: &Path, flag_label: &str) -> Result<String, String> {
    let raw =
        fs::read(path).map_err(|e| format!("cannot read {flag_label} {}: {e}", path.display()))?;
    if let Ok(txt) = std::str::from_utf8(&raw) {
        if txt.trim().contains("PRIVATE KEY-----") {
            return Err(format!(
                "{flag_label} {} contains a private key PEM; pass --releaser-key-file instead",
                path.display()
            ));
        }
    }
    let entry = parse_public_key_entry(&raw, None, flag_label)?;
    Ok(entry.keyid)
}

fn resolve_releaser_key_id(
    releaser_pubkey_file: Option<&Path>,
    releaser_key_file: Option<&Path>,
    releaser_key_id: Option<&str>,
) -> Result<String, String> {
    let mut resolved: Option<String> = None;

    if let Some(pub_path) = releaser_pubkey_file {
        let kid = parse_pubkey_file_to_key_id(pub_path, "--releaser-pubkey-file")?;
        resolved = Some(kid);
    }

    if let Some(key_path) = releaser_key_file {
        let raw_check = fs::read(key_path).map_err(|e| {
            format!(
                "cannot read --releaser-key-file {}: {e}",
                key_path.display()
            )
        })?;
        if std::str::from_utf8(&raw_check)
            .ok()
            .is_some_and(|t| t.contains("-----BEGIN PUBLIC KEY-----"))
        {
            return Err(format!(
                "--releaser-key-file {} contains a public key PEM; pass --releaser-pubkey-file instead",
                key_path.display()
            ));
        }
        let sk = load_signing_key_file(key_path, "--releaser-key-file")?;
        let kid = ed25519_key_id(&sk.verifying_key().to_bytes());
        if let Some(ref prev) = resolved {
            if prev != &kid {
                return Err(format!(
                    "--releaser-pubkey-file ({prev}) and --releaser-key-file ({kid}) derive different key IDs"
                ));
            }
        }
        resolved = Some(kid);
    }

    if let Some(explicit_kid) = releaser_key_id.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(ref prev) = resolved {
            if prev != explicit_kid {
                return Err(format!(
                    "derived releaser key ID ({prev}) does not match --releaser-key-id ({explicit_kid})"
                ));
            }
        }
        resolved = Some(explicit_kid.to_string());
    }

    resolved.ok_or_else(|| {
        "no releaser key supplied: pass --releaser-pubkey-file <path>, --releaser-key-file <path>, or --releaser-key-id <keyid>"
            .to_string()
    })
}

fn resolve_releaser_signing_key(
    releaser_key_file: Option<&Path>,
    releaser_seed_env: &str,
) -> Result<SigningKey, String> {
    if let Some(path) = releaser_key_file {
        return load_signing_key_file(path, "--releaser-key-file");
    }
    if let Some(env_val) = std::env::var(releaser_seed_env)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        return parse_ed25519_signing_key_bytes(env_val.as_bytes(), releaser_seed_env);
    }
    Err(format!(
        "no releaser signing key supplied: pass --releaser-key-file <path> or set environment variable {releaser_seed_env}"
    ))
}

fn resolve_bearer_token(
    bearer_token_file: Option<&Path>,
    bearer_token_env: &str,
) -> Result<String, String> {
    if let Some(path) = bearer_token_file {
        #[cfg(unix)]
        if let Ok(meta) = fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                eprintln!(
                    "r5e-endpoint-helper: warning: bearer token file {} has mode {:04o} (recommended 0600)",
                    path.display(),
                    mode
                );
            }
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("cannot read --bearer-token-file {}: {e}", path.display()))?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(format!("--bearer-token-file {} is empty", path.display()));
        }
        return Ok(trimmed);
    }
    if let Some(val) = std::env::var(bearer_token_env)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return Ok(val);
    }
    Err(format!(
        "no bearer token supplied: set environment variable {bearer_token_env} (or pass --bearer-token-file <path>)"
    ))
}

fn load_signing_key_file(path: &Path, flag_label: &str) -> Result<SigningKey, String> {
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if (mode & 0o077) != 0 {
            eprintln!(
                "r5e-endpoint-helper: warning: private key file {} has mode {:04o} (recommended 0600)",
                path.display(),
                mode
            );
        }
    }
    let raw =
        fs::read(path).map_err(|e| format!("cannot read {flag_label} {}: {e}", path.display()))?;
    parse_ed25519_signing_key_bytes(&raw, flag_label)
}

fn generate_and_save_recovery_key(path: &Path, force: bool) -> Result<(String, String), String> {
    let seed = generate_os_random_seed_32()?;
    write_private_key_file_0600(path, &seed, force)?;
    let sk = SigningKey::from_bytes(&seed);
    let key_id = ed25519_key_id(&sk.verifying_key().to_bytes());
    Ok((key_id, path.to_string_lossy().into_owned()))
}

fn resolve_root_signing_key(
    root_seed_file: Option<&Path>,
    root_seed_env: &str,
    generate_root_seed_out: Option<&Path>,
    force: bool,
    allow_ephemeral_fallback: bool,
) -> Result<SigningKey, String> {
    if root_seed_file.is_some() && generate_root_seed_out.is_some() {
        return Err("cannot pass both --root-seed-file and --generate-root-seed-out".to_string());
    }
    if let Some(path) = root_seed_file {
        return load_signing_key_file(path, "--root-seed-file");
    }
    if let Some(env_val) = std::env::var(root_seed_env)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        if generate_root_seed_out.is_some() {
            return Err(format!(
                "cannot use --generate-root-seed-out when environment variable {root_seed_env} is already set"
            ));
        }
        return parse_ed25519_signing_key_bytes(env_val.as_bytes(), root_seed_env);
    }
    if let Some(out_path) = generate_root_seed_out {
        let seed = generate_os_random_seed_32()?;
        write_private_key_file_0600(out_path, &seed, force)?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    if allow_ephemeral_fallback {
        let seed = generate_os_random_seed_32()?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    Err(format!(
        "no root signing seed supplied: provide --root-seed-file <path>, set {root_seed_env}, or pass --generate-root-seed-out <path>"
    ))
}

fn resolve_claim_code(
    claim_code_file: Option<&Path>,
    claim_code_env: &str,
) -> Result<String, String> {
    if let Some(path) = claim_code_file {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("cannot read --claim-code-file {}: {e}", path.display()))?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(format!("--claim-code-file {} is empty", path.display()));
        }
        return Ok(trimmed);
    }
    if let Some(val) = std::env::var(claim_code_env)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return Ok(val);
    }
    Err(format!(
        "no claim code supplied: provide --claim-code-file <path> or set environment variable {claim_code_env}"
    ))
}

#[derive(Deserialize)]
struct FlexibleRootJson {
    #[serde(default)]
    key: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: SubjectPublicKey,
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    custody: Option<String>,
    #[serde(default)]
    identity: Option<String>,
}

fn parse_flexible_root_json(raw_json: &str, label: &str) -> Result<PrepareClaimRootEntry, String> {
    let parsed: FlexibleRootJson =
        serde_json::from_str(raw_json).map_err(|e| format!("invalid {label} JSON: {e}"))?;
    let alg = SignatureAlgorithm::parse(&parsed.public_key.algorithm)
        .map_err(|e| format!("{label}: {e}"))?;
    let pub_entry = parse_public_key_entry(parsed.public_key.bytes.as_bytes(), Some(alg), label)?;
    if let Some(ref declared_key) = parsed.key {
        if declared_key != &pub_entry.keyid {
            return Err(format!(
                "{label}: declared key ({declared_key}) does not match publicKey ({})",
                pub_entry.keyid
            ));
        }
    }
    Ok(PrepareClaimRootEntry {
        public_key: SubjectPublicKey {
            algorithm: pub_entry.algorithm,
            bytes: pub_entry.bytes,
        },
        holder: parsed.holder,
        custody: parsed.custody,
        identity: parsed.identity,
    })
}

fn parse_root_key_spec(spec: &str, flag_label: &str) -> Result<PrepareClaimRootEntry, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag_label} cannot be empty"));
    }
    if trimmed.starts_with('{') {
        return parse_flexible_root_json(trimmed, flag_label);
    }

    let mut parts = trimmed.split(';');
    let target = parts.next().unwrap_or_default().trim();
    let mut holder: Option<String> = None;
    let mut custody: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut alg_hint: Option<SignatureAlgorithm> = None;
    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (k, v) = attr.split_once('=').ok_or_else(|| {
            format!("invalid attribute {attr:?} in {flag_label}: expected key=value")
        })?;
        match k.trim() {
            "holder" => holder = Some(v.trim().to_string()),
            "custody" => custody = Some(v.trim().to_string()),
            "identity" => identity = Some(v.trim().to_string()),
            "algorithm" | "alg" => alg_hint = Some(SignatureAlgorithm::parse(v.trim())?),
            other => {
                return Err(format!(
                    "unknown attribute {other:?} in {flag_label} (supported: holder, custody, identity, algorithm)"
                ))
            }
        }
    }

    let target_path = Path::new(target);
    if target_path.exists() {
        let raw = fs::read(target_path)
            .map_err(|e| format!("cannot read {flag_label} {}: {e}", target_path.display()))?;
        let text_opt = std::str::from_utf8(&raw).ok().map(str::trim);
        if let Some(txt) = text_opt {
            if txt.starts_with('{') {
                if let Ok(mut entry) = parse_flexible_root_json(txt, flag_label) {
                    if holder.is_some() {
                        entry.holder = holder;
                    }
                    if custody.is_some() {
                        entry.custody = custody;
                    }
                    if identity.is_some() {
                        entry.identity = identity;
                    }
                    return Ok(entry);
                }
            }
        }
        let is_pub_file = target_path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
            || text_opt.is_some_and(|t| t.contains("-----BEGIN PUBLIC KEY-----"));

        let pub_entry = if is_pub_file {
            parse_public_key_entry(&raw, alg_hint, flag_label)?
        } else if let Ok(sk) = parse_ed25519_signing_key_bytes(&raw, flag_label) {
            let pub_bytes = sk.verifying_key().to_bytes();
            PublicKeyEntry {
                keyid: ed25519_key_id(&pub_bytes),
                algorithm: "ed25519".to_string(),
                bytes: BASE64_STANDARD.encode(pub_bytes),
            }
        } else {
            parse_public_key_entry(&raw, alg_hint, flag_label)?
        };
        return Ok(PrepareClaimRootEntry {
            public_key: SubjectPublicKey {
                algorithm: pub_entry.algorithm,
                bytes: pub_entry.bytes,
            },
            holder,
            custody,
            identity,
        });
    }

    let inline = target.strip_prefix("pub:").unwrap_or(target);
    let looks_like_missing_file = inline.ends_with(".pem")
        || inline.ends_with(".seed")
        || inline.ends_with(".key")
        || inline.ends_with(".pub")
        || inline.ends_with(".json");
    if looks_like_missing_file {
        return Err(format!(
            "cannot read {flag_label} file {target}: file does not exist"
        ));
    }

    let pub_entry = parse_public_key_entry(inline.as_bytes(), alg_hint, flag_label)?;
    Ok(PrepareClaimRootEntry {
        public_key: SubjectPublicKey {
            algorithm: pub_entry.algorithm,
            bytes: pub_entry.bytes,
        },
        holder,
        custody,
        identity,
    })
}

fn parse_additional_root_spec(spec: &str) -> Result<PrepareClaimRootEntry, String> {
    parse_root_key_spec(spec, "--additional-root")
}

fn parse_custodian_spec(spec: &str) -> Result<CustodianEntry, String> {
    let trimmed = spec.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str::<CustodianEntry>(trimmed)
            .map_err(|e| format!("invalid --custodian JSON: {e}"))
    } else if let Some((identity, key)) =
        trimmed.split_once('=').or_else(|| trimmed.split_once(','))
    {
        let id = identity.trim();
        let k = key.trim();
        if id.is_empty() || k.is_empty() {
            return Err(format!(
                "invalid --custodian spec {trimmed:?}: expected <identity>[=<keyid>] or <identity>[,<keyid>]"
            ));
        }
        Ok(CustodianEntry {
            identity: id.to_string(),
            key: Some(k.to_string()),
        })
    } else {
        if trimmed.is_empty() {
            return Err("--custodian cannot be empty".to_string());
        }
        Ok(CustodianEntry {
            identity: trimmed.to_string(),
            key: None,
        })
    }
}

fn load_custom_definition_blob(
    def_file: Option<&Path>,
    schema_override: Option<&str>,
    flag_label: &str,
) -> Result<Vec<BlobEntry>, String> {
    let Some(path) = def_file else {
        return Ok(Vec::new());
    };
    let raw =
        fs::read(path).map_err(|e| format!("cannot read {flag_label} {}: {e}", path.display()))?;
    let val: Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("invalid JSON in {flag_label} {}: {e}", path.display()))?;
    let canonical = encode_canonical_json(&val)
        .map_err(|e| format!("cannot canonicalize {flag_label} {}: {e}", path.display()))?;
    let computed_ref = bytes_ref(&canonical);
    if let Some(expected_ref) = schema_override {
        if expected_ref != computed_ref {
            return Err(format!(
                "{flag_label} canonical hash ({computed_ref}) does not match schemaRef override ({expected_ref})"
            ));
        }
    }
    Ok(vec![BlobEntry {
        blob_ref: computed_ref,
        media_type: Some("application/json".to_string()),
        base64: BASE64_STANDARD.encode(&canonical),
    }])
}

fn assemble_claim_roots_for_pubkey(
    claiming_alg: &str,
    claiming_pub_b64: &str,
    holder: Option<String>,
    custody: Option<String>,
    identity: Option<String>,
    roots_file: Option<&Path>,
    additional_roots: &[String],
) -> Result<Vec<PrepareClaimRootEntry>, String> {
    let claiming_entry = PrepareClaimRootEntry {
        public_key: SubjectPublicKey {
            algorithm: claiming_alg.to_string(),
            bytes: claiming_pub_b64.to_string(),
        },
        holder: holder.clone(),
        custody: custody.clone(),
        identity: identity.clone(),
    };

    let mut roots = Vec::new();
    let mut contains_claiming = false;

    if let Some(path) = roots_file {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("cannot read --roots-file {}: {e}", path.display()))?;
        let parsed_arr: Vec<Value> = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid JSON in --roots-file {}: {e}", path.display()))?;
        for (i, item) in parsed_arr.iter().enumerate() {
            let s = serde_json::to_string(item).unwrap();
            let mut r = parse_flexible_root_json(&s, &format!("--roots-file[{i}]"))?;
            if r.public_key.algorithm == claiming_alg && r.public_key.bytes == claiming_pub_b64 {
                contains_claiming = true;
                if r.holder.is_none() {
                    r.holder = holder.clone();
                }
                if r.custody.is_none() {
                    r.custody = custody.clone();
                }
                if r.identity.is_none() {
                    r.identity = identity.clone();
                }
            }
            roots.push(r);
        }
    }

    if !contains_claiming {
        roots.insert(0, claiming_entry);
    }

    for spec in additional_roots {
        let r = parse_additional_root_spec(spec)?;
        roots.push(r);
    }

    Ok(roots)
}

fn assemble_claim_roots(
    claiming_pub_b64: &str,
    holder: Option<String>,
    custody: Option<String>,
    identity: Option<String>,
    roots_file: Option<&Path>,
    additional_roots: &[String],
) -> Result<Vec<PrepareClaimRootEntry>, String> {
    assemble_claim_roots_for_pubkey(
        "ed25519",
        claiming_pub_b64,
        holder,
        custody,
        identity,
        roots_file,
        additional_roots,
    )
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Disclosure {
            deployed_by,
            deployed_at,
            posture,
            json,
        } => {
            let p: Posture = posture.into();
            let disclosure = HelperDisclosure {
                deployed_by,
                deployed_at,
                policy_bundle_ref: "cached-local-bundle".to_string(),
                posture: format!("{p:?}").to_lowercase(),
                watched_harnesses: vec!["claude".to_string(), "codex".to_string()],
                collected_fields: vec![
                    "Session URN, harness version, and device key ID".to_string(),
                    "Local child commands and local MCP tool calls started by watched harnesses"
                        .to_string(),
                    "Policy decision (allowed, prevented, or observed) and rule ID".to_string(),
                ],
                never_collected: NEVER_COLLECTED.iter().map(|s| (*s).to_string()).collect(),
                retention_summary: "Governed by your organisation's retention schedule".to_string(),
                authorized_readers: vec![
                    "Authorised internal auditors (under audited ReadReceipts policy)".to_string(),
                    "You, for every session recorded in your name".to_string(),
                ],
                self_record_url: "/admin/timeline?principal=self".to_string(),
                supervision_boundary: SUPERVISION_BOUNDARY_STATEMENT.to_string(),
                recent_sent_items: vec![],
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&disclosure).expect("serialize disclosure")
                );
            } else {
                print!("{}", disclosure.render_plain_text());
            }
        }
        Commands::ExecGate {
            policy_file,
            posture,
            agent_id,
            session,
            offline,
            argv,
        } => {
            let cedar_src = match fs::read_to_string(&policy_file) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: cannot read policy file: {err}");
                    exit(2);
                }
            };
            let gate = match LocalCedarGate::from_cedar_src(&cedar_src, posture.into(), offline) {
                Ok(g) => g,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };
            let program = argv[0].clone();
            let command_line = argv.join(" ");
            let action = LocalActionKind::ExecCommand {
                program: program.clone(),
                argv: argv[1..].to_vec(),
                command_line,
            };
            let verdict = match gate.evaluate(&agent_id, &session, &action) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: policy evaluation error: {err}");
                    exit(2);
                }
            };
            if !verdict.allowed_to_execute {
                if let Some(msg) = &verdict.agent_message {
                    eprintln!("{msg}");
                }
                exit(126);
            }
            let status = Command::new(&program)
                .args(&argv[1..])
                .status()
                .unwrap_or_else(|err| {
                    eprintln!("r5e-endpoint-helper: failed to execute {program}: {err}");
                    exit(127);
                });
            exit(status.code().unwrap_or(1));
        }
        Commands::McpWrap {
            server_id,
            policy_file,
            posture,
            agent_id,
            session,
            argv,
        } => {
            let cedar_src = match fs::read_to_string(&policy_file) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: cannot read policy file: {err}");
                    exit(2);
                }
            };
            let gate = match LocalCedarGate::from_cedar_src(&cedar_src, posture.into(), false) {
                Ok(g) => g,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };
            let mut child = Command::new(&argv[0])
                .args(&argv[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap_or_else(|err| {
                    eprintln!("r5e-endpoint-helper: failed to spawn MCP server: {err}");
                    exit(127);
                });

            let mut child_stdin = child.stdin.take().expect("child stdin");
            let child_stdout = child.stdout.take().expect("child stdout");
            let mut child_reader = io::BufReader::new(child_stdout);
            let mut guard = McpStdioSessionGuard::new(server_id);

            let stdin = io::stdin();
            let mut stdout = io::stdout();
            for line in stdin.lock().lines() {
                let raw = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if raw.trim().is_empty() {
                    continue;
                }
                let parsed: Value = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match guard.inspect_client_request(&parsed, &agent_id, &session, &gate) {
                    Ok(ClientFrameDisposition::Forward { .. }) => {
                        if writeln!(child_stdin, "{raw}").is_err() || child_stdin.flush().is_err() {
                            break;
                        }
                        let mut resp_line = String::new();
                        if child_reader.read_line(&mut resp_line).unwrap_or(0) == 0 {
                            break;
                        }
                        if let Ok(resp_val) = serde_json::from_str::<Value>(&resp_line) {
                            let _ = guard.observe_server_response(&resp_val);
                        }
                        let _ = write!(stdout, "{resp_line}");
                        let _ = stdout.flush();
                    }
                    Ok(ClientFrameDisposition::InterceptWithResponse {
                        synthetic_response,
                        ..
                    }) => {
                        let _ = writeln!(stdout, "{synthetic_response}");
                        let _ = stdout.flush();
                    }
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: MCP gate error: {err}");
                    }
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        Commands::EnrolSmoke {
            gateway_url,
            token_env,
            token_file,
            holder,
            actor,
            session,
            out_bundle,
        } => {
            let bearer = match token_file {
                Some(path) => match fs::read_to_string(&path) {
                    Ok(raw) => Some(raw.trim().to_string()).filter(|s| !s.is_empty()),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: cannot read token file: {err}");
                        exit(2);
                    }
                },
                None => std::env::var(&token_env).ok().filter(|s| !s.is_empty()),
            };
            let cfg = EnrolmentClientConfig::new(gateway_url, bearer);
            let key_seed = generate_os_random_seed_32().unwrap_or_else(|e| {
                eprintln!("r5e-endpoint-helper: {e}");
                exit(1);
            });
            let helper_key = SigningKey::from_bytes(&key_seed);

            let smoke_cedar = r#"
permit(
    principal,
    action == Recurse::Action::"InvokeMcpTool",
    resource == Recurse::McpTool::"filesystem:read_file"
);
"#;
            let gate = LocalCedarGate::from_cedar_src(smoke_cedar, Posture::Enforce, false)
                .expect("valid smoke Cedar policy");

            let mut enrolled = match enrol_endpoint_badge(
                &cfg,
                helper_key,
                &holder,
                None,
                vec![
                    "provenance.r5e.io/v2/SessionOpened".to_string(),
                    "provenance.r5e.io/v2/ToolCall".to_string(),
                    "provenance.r5e.io/v2/SessionClosed".to_string(),
                ],
                Some(vec![actor.clone()]),
                Some(3600),
                smoke_cedar.as_bytes(),
            ) {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: enrolment failed: {err}");
                    exit(1);
                }
            };

            let now_utc = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            if let Err(err) = enrolled.record_v2_event(
                "smoke",
                "SessionOpened",
                &actor,
                Some(&session),
                &now_utc,
                json!({ "session": &session }),
            ) {
                eprintln!("r5e-endpoint-helper: failed recording SessionOpened: {err}");
                exit(1);
            }

            let mcp_guard = McpStdioSessionGuard::new("filesystem");
            let blocked_req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "delete_file", "arguments": { "path": "prod.db" } }
            });
            let disp = mcp_guard
                .inspect_client_request(&blocked_req, "endpoint-smoke", &session, &gate)
                .expect("MCP stdio Cedar check");
            assert!(matches!(
                disp,
                ClientFrameDisposition::InterceptWithResponse { .. }
            ));

            let args_bytes = encode_canonical_json(&blocked_req["params"]["arguments"]).unwrap();
            let args_ref = enrolled
                .recorder
                .put_blob(&args_bytes, Some("application/json"));
            let policy_ref = enrolled.deployment_policy_ref.clone();

            let tool_call_rec = match enrolled.record_v2_event(
                "smoke",
                "ToolCall",
                &actor,
                Some(&session),
                &now_utc,
                json!({
                    "tool": "filesystem:delete_file",
                    "contentRef": &args_ref,
                    "mediaType": "application/json",
                    "size": args_bytes.len() as i64,
                    "policy": {
                        "policyRef": &policy_ref,
                        "outcome": "deny",
                        "inputRefs": [&args_ref],
                        "reason": "Cedar 4.9.1 withheld unpermitted MCP tool filesystem:delete_file",
                    },
                    "result": {
                        "outcome": "denied",
                        "outputRefs": [],
                        "reason": "Prevented on endpoint before child stdin",
                    }
                }),
            ) {
                Ok(rec) => rec,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: failed recording ToolCall: {err}");
                    exit(1);
                }
            };

            let smoke_stream = format!("{}smoke", enrolled.stream_prefix);
            if let Err(err) = enrolled.record_v2_event(
                "smoke",
                "SessionClosed",
                &actor,
                Some(&session),
                &now_utc,
                json!({
                    "session": &session,
                    "outcome": "completed",
                    "through": [
                        {
                            "stream": &smoke_stream,
                            "seq": 2,
                            "event": &tool_call_rec.record_ref,
                        }
                    ]
                }),
            ) {
                eprintln!("r5e-endpoint-helper: failed recording SessionClosed: {err}");
                exit(1);
            }

            let bundle_bytes = match enrolled
                .recorder
                .export_v2_bundle_bytes(json!({ "session": &session }))
            {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: bundle export failed: {err}");
                    exit(1);
                }
            };
            if let Err(err) = fs::write(&out_bundle, &bundle_bytes) {
                eprintln!("r5e-endpoint-helper: cannot write bundle: {err}");
                exit(1);
            }
            let summary = encode_canonical_json(&json!({
                "ok": true,
                "badgeRef": enrolled.badge_ref,
                "helperKeyId": enrolled.helper_keyid,
                "streamPrefix": enrolled.stream_prefix,
                "actsFor": enrolled.acts_for,
                "bundlePath": out_bundle.to_string_lossy(),
            }))
            .unwrap();
            println!("{}", String::from_utf8_lossy(&summary));
        }
        Commands::DeploymentStatus { gateway_url } => {
            let cfg = ClaimClientConfig::new(gateway_url);
            let status = match get_deployment_status(&cfg) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: GET /v1/deployment failed: {err}");
                    exit(1);
                }
            };
            let out_val = serde_json::to_value(&status).expect("serialize deployment status");
            let canonical = encode_canonical_json(&out_val).expect("canonical status JSON");
            println!("{}", String::from_utf8_lossy(&canonical));
        }
        Commands::Claim {
            gateway_url,
            claim_code_file,
            claim_code_env,
            root_seed_file,
            root_seed_env,
            generate_root_seed_out,
            holder,
            custody,
            identity,
            roots_file,
            additional_roots,
            threshold,
            recovery_keys,
            generate_recovery_keys,
            custodians,
            allow_permanent_roots,
            force,
            trusted_publishers,
            allow_untrusted_publisher,
            grant_gateway,
            skip_gateway_grant,
            grant_ttl_seconds,
            grant_actor,
            grant_kinds,
            out_receipt,
        } => {
            if trusted_publishers.is_empty() && !allow_untrusted_publisher {
                eprintln!(
                    "r5e-endpoint-helper: refusing claim without publisher trust pin: pass --trusted-publisher <keyid> or --allow-untrusted-publisher"
                );
                exit(2);
            }

            let mut parsed_custodians = Vec::with_capacity(custodians.len());
            for c_spec in &custodians {
                match parse_custodian_spec(c_spec) {
                    Ok(c) => parsed_custodians.push(c),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }

            // §5.5 Irreversibility warning & permanent-roots guard BEFORE writing any key files:
            if recovery_keys.is_empty()
                && generate_recovery_keys.is_empty()
                && parsed_custodians.is_empty()
            {
                eprintln!("{IRREVERSIBLE_CLAIM_WARNING}");
                if !allow_permanent_roots {
                    eprintln!(
                        "r5e-endpoint-helper: refusing permanent unrotatable root configuration: pass --generate-recovery-key <path>, --recovery-key <keyid>, or --custodian <uri>[=<keyid>], or pass --allow-permanent-roots to confirm"
                    );
                    exit(2);
                }
            }

            let code = match resolve_claim_code(claim_code_file.as_deref(), &claim_code_env) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let root_signing_key = match resolve_root_signing_key(
                root_seed_file.as_deref(),
                &root_seed_env,
                generate_root_seed_out.as_deref(),
                force,
                false,
            ) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let mut all_recovery_keys = recovery_keys;
            let mut generated_recovery_meta = Vec::with_capacity(generate_recovery_keys.len());
            for rec_path in &generate_recovery_keys {
                match generate_and_save_recovery_key(rec_path, force) {
                    Ok((kid, saved_path)) => {
                        all_recovery_keys.push(kid.clone());
                        generated_recovery_meta.push(json!({
                            "keyId": kid,
                            "path": saved_path,
                        }));
                    }
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }

            let root_pub_bytes = root_signing_key.verifying_key().to_bytes();
            let root_key_id = ed25519_key_id(&root_pub_bytes);
            let root_pub_b64 = BASE64_STANDARD.encode(root_pub_bytes);

            let roots = match assemble_claim_roots(
                &root_pub_b64,
                holder,
                custody,
                identity,
                roots_file.as_deref(),
                &additional_roots,
            ) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let prepare_req = PrepareClaimRequest {
                code,
                claimed_by: root_key_id.clone(),
                roots,
                threshold,
                recovery_keys: if all_recovery_keys.is_empty() {
                    None
                } else {
                    Some(all_recovery_keys.clone())
                },
                custodians: if parsed_custodians.is_empty() {
                    None
                } else {
                    Some(parsed_custodians)
                },
            };

            let should_grant = grant_gateway && !skip_gateway_grant;
            let cfg = ClaimClientConfig::new(gateway_url);

            let outcome = match execute_claim_ceremony(
                &cfg,
                &root_signing_key,
                &prepare_req,
                &trusted_publishers,
                allow_untrusted_publisher,
                should_grant,
                grant_ttl_seconds,
                &grant_actor,
                grant_kinds,
            ) {
                Ok(o) => o,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: deployment claim failed: {err}");
                    exit(1);
                }
            };

            let endorsement_ref = outcome
                .gateway_grant
                .as_ref()
                .map(|(built, _)| built.endorsement.record_ref.clone());

            if let Some(ref receipt_path) = out_receipt {
                let mut receipt_obj = json!({
                    "chain": &outcome.finalized.chain,
                    "deployment": &outcome.inspection.deployment,
                    "deploymentRecord": &outcome.finalized.deployment_record,
                    "chainStarted": &outcome.finalized.chain_started,
                    "gatewayKey": &outcome.finalized.gateway_key,
                    "streamPrefix": &outcome.finalized.stream_prefix,
                    "rootKeyId": &root_key_id,
                    "recoveryKeys": &all_recovery_keys,
                    "publisher": &outcome.inspection.publisher_key_id,
                    "publisherTrusted": outcome.inspection.publisher_trusted,
                    "publicationRef": &outcome.inspection.publication_ref,
                    "definitionCount": outcome.inspection.definition_count,
                    "endorsementRef": &endorsement_ref,
                    "gatewayGrantSubmitted": outcome.gateway_grant.is_some(),
                });
                if !generated_recovery_meta.is_empty() {
                    let obj = receipt_obj.as_object_mut().unwrap();
                    obj.insert(
                        "generatedRecoveryKeys".to_string(),
                        json!(&generated_recovery_meta),
                    );
                    if generated_recovery_meta.len() == 1 {
                        obj.insert(
                            "generatedRecoveryKey".to_string(),
                            generated_recovery_meta[0].clone(),
                        );
                    }
                }
                if let Some((ref built, _)) = outcome.gateway_grant {
                    receipt_obj
                        .as_object_mut()
                        .unwrap()
                        .insert("endorsement".to_string(), json!(&built.endorsement));
                }
                let receipt_bytes = encode_canonical_json(&receipt_obj).unwrap_or_else(|e| {
                    eprintln!("r5e-endpoint-helper: failed encoding receipt JSON: {e}");
                    exit(1);
                });
                if let Err(err) = fs::write(receipt_path, &receipt_bytes) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot write --out-receipt {}: {err}",
                        receipt_path.display()
                    );
                    exit(1);
                }
            }

            let mut summary_obj = json!({
                "ok": true,
                "deployment": outcome.inspection.deployment,
                "chain": outcome.finalized.chain,
                "chainStartedRef": outcome.finalized.chain_started.record_ref,
                "rootKeyId": root_key_id,
                "recoveryKeys": all_recovery_keys,
                "gatewayKey": outcome.finalized.gateway_key,
                "gatewayKeyId": outcome.finalized.gateway_key.keyid,
                "streamPrefix": outcome.finalized.stream_prefix,
                "publisher": outcome.inspection.publisher_key_id,
                "publisherTrusted": outcome.inspection.publisher_trusted,
                "publicationRef": outcome.inspection.publication_ref,
                "definitionCount": outcome.inspection.definition_count,
                "endorsementRef": endorsement_ref,
                "gatewayGrantSubmitted": outcome.gateway_grant.is_some(),
            });
            if !generated_recovery_meta.is_empty() {
                let obj = summary_obj.as_object_mut().unwrap();
                obj.insert(
                    "generatedRecoveryKeys".to_string(),
                    json!(&generated_recovery_meta),
                );
                if generated_recovery_meta.len() == 1 {
                    obj.insert(
                        "generatedRecoveryKey".to_string(),
                        generated_recovery_meta[0].clone(),
                    );
                }
            }
            if let Some(ref p) = out_receipt {
                summary_obj.as_object_mut().unwrap().insert(
                    "receiptPath".to_string(),
                    Value::String(p.to_string_lossy().into_owned()),
                );
            }
            if let Some(ref p) = generate_root_seed_out {
                summary_obj.as_object_mut().unwrap().insert(
                    "generatedRootSeedPath".to_string(),
                    Value::String(p.to_string_lossy().into_owned()),
                );
            }
            let summary_bytes = encode_canonical_json(&summary_obj).expect("canonical summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::GrantGateway {
            gateway_url,
            root_seed_file,
            root_seed_env,
            gateway_key_id,
            deployment,
            stream_prefix,
            seq,
            previous,
            actor,
            kinds,
            not_before,
            ttl_seconds,
            may_endorse,
            out_grant_file,
        } => {
            let root_signing_key = match resolve_root_signing_key(
                root_seed_file.as_deref(),
                &root_seed_env,
                None,
                false,
                false,
            ) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let cfg = ClaimClientConfig::new(gateway_url);

            let need_status =
                gateway_key_id.is_none() || (stream_prefix.is_none() && deployment.is_none());
            let fetched_status = if need_status {
                match get_deployment_status_raw(&cfg) {
                    Ok(pair) => Some(pair),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: GET /v1/deployment failed: {err}");
                        exit(1);
                    }
                }
            } else {
                None
            };

            let resolved_gw_key_id = match gateway_key_id.or_else(|| {
                fetched_status
                    .as_ref()
                    .and_then(|(s, _)| s.gateway_key.as_ref().map(|k| k.keyid.clone()))
            }) {
                Some(id) => id,
                None => {
                    eprintln!(
                        "r5e-endpoint-helper: gatewayKey was not provided via --gateway-key-id and was not advertised by GET /v1/deployment"
                    );
                    exit(2);
                }
            };

            let resolved_prefix = if let Some(sp) = stream_prefix {
                sp
            } else if let Some(dep) = deployment {
                format!("urn:r5e:stream:{dep}:")
            } else if let Some(sp) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.stream_prefix.clone())
            {
                sp
            } else if let Some(dep) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.deployment.clone())
            {
                format!("urn:r5e:stream:{dep}:")
            } else {
                eprintln!(
                    "r5e-endpoint-helper: could not determine deployment stream prefix; pass --deployment <slug> or --stream-prefix <prefix>"
                );
                exit(2);
            };

            let mut params = GatewayGrantParams::new(resolved_gw_key_id.clone(), resolved_prefix);
            if let Some(admitted_at) = fetched_status.as_ref().and_then(|(s, raw)| {
                latest_status_captured_at_utc(raw).or_else(|| {
                    s.deployment_record
                        .as_ref()
                        .and_then(record_captured_at_utc)
                })
            }) {
                params.captured_at = Some(std::cmp::max(
                    chrono::Utc::now(),
                    ceil_to_micros(admitted_at),
                ));
            }
            params.seq = seq;
            params.previous = previous;
            params.actor = actor;
            if let Some(k) = kinds {
                params.kinds = k;
            }
            params.not_before_override = not_before;
            params.ttl_seconds = ttl_seconds;
            params.may_endorse = may_endorse;

            let built = match build_root_gateway_grant(&root_signing_key, &params) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: invalid gateway grant parameters: {err}");
                    exit(2);
                }
            };

            if let Some(ref path) = out_grant_file {
                let grant_bytes = encode_canonical_json(
                    &serde_json::to_value(&built.request).expect("serialize grant request"),
                )
                .expect("canonical grant JSON");
                if let Err(err) = fs::write(path, &grant_bytes) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot write --out-grant-file {}: {err}",
                        path.display()
                    );
                    exit(1);
                }
            }

            let submit_resp = match submit_deployment_grants(&cfg, &built.request) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: POST /v1/deployment/grants failed: {err}");
                    exit(1);
                }
            };

            let out_summary = encode_canonical_json(&json!({
                "ok": true,
                "status": submit_resp.status,
                "rootKeyId": built.root_key_id,
                "gatewayKeyId": resolved_gw_key_id,
                "rootStream": built.root_stream,
                "seq": seq,
                "endorsementRef": built.endorsement.record_ref,
                "profileRef": built.root_profile_ref,
                "recordedRefs": submit_resp.recorded_refs,
            }))
            .expect("canonical grant summary");
            println!("{}", String::from_utf8_lossy(&out_summary));
        }
        Commands::RevokeGrant {
            gateway_url,
            targets,
            issuer,
            reason,
            root_key_file,
            root_seed_env,
            deployment,
            stream_prefix,
            actor,
            dry_run_out,
            out_revocation_file,
        } => {
            if targets.is_empty() && issuer.is_none() {
                eprintln!(
                    "r5e-endpoint-helper: revoke-grant requires --target <evidence:sha256:...> and/or --issuer <key:ed25519:sha256:...>"
                );
                exit(2);
            }
            if issuer.is_some() && gateway_url.is_none() {
                eprintln!(
                    "r5e-endpoint-helper: revoke-grant --issuer requires --gateway-url <url> to query held grants from GET /v1/deployment"
                );
                exit(2);
            }
            if gateway_url.is_none() && dry_run_out.is_none() {
                eprintln!(
                    "r5e-endpoint-helper: revoke-grant requires --gateway-url <url> (or --dry-run-out <file> for offline payload generation)"
                );
                exit(2);
            }

            let signer_key = match resolve_root_signing_key(
                root_key_file.as_deref(),
                &root_seed_env,
                None,
                false,
                false,
            ) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let explicit_prefix =
                stream_prefix.or_else(|| deployment.map(|dep| format!("urn:r5e:stream:{dep}:")));

            let cfg_opt = gateway_url.as_deref().map(ClaimClientConfig::new);
            let fetched_status =
                if issuer.is_some() || (cfg_opt.is_some() && explicit_prefix.is_none()) {
                    let cfg = cfg_opt.as_ref().expect("gateway_url checked Some");
                    match get_deployment_status_raw(cfg) {
                        Ok(pair) => Some(pair),
                        Err(err) => {
                            eprintln!("r5e-endpoint-helper: GET /v1/deployment failed: {err}");
                            exit(1);
                        }
                    }
                } else if let (Some(cfg), None) = (&cfg_opt, &dry_run_out) {
                    get_deployment_status_raw(cfg).ok()
                } else {
                    None
                };

            let mut all_targets: Vec<String> = Vec::new();
            if let Some(ref iss_id) = issuer {
                let (status, raw) = fetched_status
                    .as_ref()
                    .expect("status fetched when issuer is Some");
                match select_unrevoked_grants_by_issuer(status, Some(raw), iss_id) {
                    Ok(selected) => {
                        for r in selected {
                            if !all_targets.iter().any(|existing| existing == &r) {
                                all_targets.push(r);
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }
            for t in &targets {
                if !all_targets.iter().any(|existing| existing == t) {
                    all_targets.push(t.clone());
                }
            }

            let resolved_prefix = if let Some(sp) = explicit_prefix {
                sp
            } else if let Some(sp) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.stream_prefix.clone())
            {
                sp
            } else if let Some(dep) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.deployment.clone())
            {
                format!("urn:r5e:stream:{dep}:")
            } else {
                eprintln!(
                    "r5e-endpoint-helper: could not determine deployment stream prefix; pass --deployment <slug> or --stream-prefix <prefix>"
                );
                exit(2);
            };

            let captured_at = fetched_status
                .as_ref()
                .and_then(|(s, raw)| {
                    latest_status_captured_at_utc(raw).or_else(|| {
                        s.deployment_record
                            .as_ref()
                            .and_then(record_captured_at_utc)
                    })
                })
                .map(|admitted_floor| {
                    std::cmp::max(chrono::Utc::now(), ceil_to_micros(admitted_floor))
                });

            let batch = match build_grant_revocations_batch(
                &signer_key,
                &all_targets,
                resolved_prefix,
                reason.clone(),
                actor,
                captured_at,
            ) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: invalid revocation parameters: {err}");
                    exit(2);
                }
            };

            let req_bytes = encode_canonical_json(
                &serde_json::to_value(&batch.request).expect("serialize revocation request"),
            )
            .expect("canonical revocation JSON");

            for maybe_path in [&dry_run_out, &out_revocation_file].into_iter().flatten() {
                if let Some(parent) = maybe_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(err) = fs::create_dir_all(parent) {
                            eprintln!(
                                "r5e-endpoint-helper: cannot create parent dir for {}: {err}",
                                maybe_path.display()
                            );
                            exit(1);
                        }
                    }
                }
                if let Err(err) = fs::write(maybe_path, &req_bytes) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot write revocation payload {}: {err}",
                        maybe_path.display()
                    );
                    exit(1);
                }
            }

            let revocation_refs: Vec<String> = batch
                .items
                .iter()
                .map(|i| i.revocation.record_ref.clone())
                .collect();
            let revocation_streams: Vec<String> = batch
                .items
                .iter()
                .map(|i| i.revocation_stream.clone())
                .collect();
            let profile_refs: Vec<String> =
                batch.items.iter().map(|i| i.profile_ref.clone()).collect();

            let mut summary = json!({
                "ok": true,
                "revokerKeyId": batch.revoker_key_id,
                "count": batch.items.len(),
                "targets": all_targets,
                "reason": reason,
                "revocationStreams": revocation_streams,
                "revocationRefs": revocation_refs,
                "profileRefs": profile_refs,
                "safetyNote": REVOCATION_ROTATION_SAFETY_NOTE,
            });
            {
                let obj = summary.as_object_mut().unwrap();
                if let Some(iss) = issuer {
                    obj.insert("issuer".to_string(), Value::String(iss));
                }
                if batch.items.len() == 1 {
                    let item = &batch.items[0];
                    obj.insert("target".to_string(), Value::String(all_targets[0].clone()));
                    obj.insert(
                        "revocationStream".to_string(),
                        Value::String(item.revocation_stream.clone()),
                    );
                    obj.insert("seq".to_string(), json!(1));
                    obj.insert(
                        "revocationRef".to_string(),
                        Value::String(item.revocation.record_ref.clone()),
                    );
                    obj.insert(
                        "profileRef".to_string(),
                        Value::String(item.profile_ref.clone()),
                    );
                }
            }

            if let Some(ref dry_path) = dry_run_out {
                let obj = summary.as_object_mut().unwrap();
                obj.insert("submitted".to_string(), json!(false));
                obj.insert(
                    "dryRunOut".to_string(),
                    Value::String(dry_path.to_string_lossy().into_owned()),
                );
                let out_summary =
                    encode_canonical_json(&summary).expect("canonical dry-run revocation summary");
                println!("{}", String::from_utf8_lossy(&out_summary));
            } else {
                let cfg = cfg_opt.expect("gateway_url checked Some when dry_run_out is None");
                let submit_resp = match submit_deployment_revocations(&cfg, &batch.request) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: POST /v1/deployment/revocations failed: {err}"
                        );
                        exit(1);
                    }
                };

                let obj = summary.as_object_mut().unwrap();
                obj.insert("submitted".to_string(), json!(true));
                obj.insert("status".to_string(), json!(submit_resp.status));
                obj.insert("recordedRefs".to_string(), json!(submit_resp.recorded_refs));
                let out_summary =
                    encode_canonical_json(&summary).expect("canonical revocation summary");
                println!("{}", String::from_utf8_lossy(&out_summary));
            }
        }
        Commands::MintGatewayAuthority {
            gateway_key_id,
            deployment,
            actor,
            kinds,
            ttl_seconds,
            root_seed_file,
            root_seed_env,
            generate_root_seed_out,
            out_authority_file,
        } => {
            let root_key = match resolve_root_signing_key(
                root_seed_file.as_deref(),
                &root_seed_env,
                generate_root_seed_out.as_deref(),
                false,
                true,
            ) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let root_pub_bytes = root_key.verifying_key().to_bytes();
            let root_key_id = ed25519_key_id(&root_pub_bytes);
            let root_pub_b64 = BASE64_STANDARD.encode(root_pub_bytes);
            let root_hex = root_key_id
                .strip_prefix("key:ed25519:sha256:")
                .expect("ed25519 keyid prefix");

            let schemas = base_v2_schema_map();
            let endorsement_schema = schemas["provenance.r5e.io/v2/Endorsement"]
                .as_str()
                .unwrap()
                .to_string();

            let root_stream = format!("urn:r5e:stream:{deployment}:authority:root:{root_hex}");
            let root_policy_bytes = b"permit(principal, action, resource);";
            let policy_ref = bytes_ref(root_policy_bytes);
            let root_profile = encode_canonical_json(&json!({
                "format": "r5e.capture-profile/v2",
                "schemas": schemas,
                "authority": {
                    "bindings": [
                        {
                            "streamPrefix": &root_stream,
                            "actorPrefixes": ["urn:r5e:"],
                            "issuerKeys": [&root_key_id],
                            "sealerKeys": [&gateway_key_id],
                        }
                    ],
                    "checkpointKeys": [],
                },
                "durability": {
                    "failureDomain": "offline-operator-root",
                    "requiredPayloads": "submitted",
                    "onFailure": "refuse",
                },
                "policyRequiredKinds": [],
                "deploymentPolicyRef": &policy_ref,
            }))
            .unwrap();
            let root_profile_ref = bytes_ref(&root_profile);

            let now = chrono::Utc::now();
            let not_before = (now - chrono::Duration::seconds(60))
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let not_after = (now + chrono::Duration::seconds(ttl_seconds as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let captured_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

            let effective_kinds = kinds.unwrap_or_else(default_gateway_grant_kinds);

            let endorsement = sign_v2_record_multi(
                &[&root_key],
                json!({
                    "apiVersion": "provenance.r5e.io/v2",
                    "kind": "Endorsement",
                    "schemaRef": &endorsement_schema,
                    "profileRef": &root_profile_ref,
                    "stream": &root_stream,
                    "seq": 1,
                    "previous": null,
                    "actor": &actor,
                    "capturedAt": &captured_at,
                    "body": {
                        "subject": &gateway_key_id,
                        "kinds": effective_kinds,
                        "streamPrefixes": [format!("urn:r5e:stream:{deployment}:")],
                        "actorPrefixes": ["urn:r5e:"],
                        "mayEndorse": true,
                        "notBefore": &not_before,
                        "notAfter": &not_after,
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            )
            .unwrap_or_else(|e| {
                eprintln!("r5e-endpoint-helper: failed signing root Endorsement: {e}");
                exit(1);
            });

            let authority_file_bytes = encode_canonical_json(&json!({
                "records": [&endorsement],
                "keys": [
                    PublicKeyEntry {
                        keyid: root_key_id.clone(),
                        algorithm: "ed25519".to_string(),
                        bytes: root_pub_b64,
                    }
                ],
                "blobs": [
                    {
                        "ref": &root_profile_ref,
                        "mediaType": "application/json",
                        "base64": BASE64_STANDARD.encode(&root_profile),
                    }
                ]
            }))
            .unwrap();

            if let Err(err) = fs::write(&out_authority_file, &authority_file_bytes) {
                eprintln!("r5e-endpoint-helper: cannot write authority file: {err}");
                exit(1);
            }

            let out_summary = encode_canonical_json(&json!({
                "ok": true,
                "rootKeyId": root_key_id,
                "gatewayKeyId": gateway_key_id,
                "endorsementRef": endorsement.record_ref,
                "authorityFile": out_authority_file.to_string_lossy(),
            }))
            .unwrap();
            println!("{}", String::from_utf8_lossy(&out_summary));
        }
        Commands::ProposeRootChange {
            deployment,
            chain,
            replaces,
            seq,
            authorization,
            signer_key,
            root_keys,
            roots_file,
            additional_roots,
            threshold,
            recovery_keys,
            generate_recovery_keys,
            force,
            custodians,
            reason,
            actor,
            roots_changed_schema_ref,
            approval_schema_ref,
            roots_changed_definition_file,
            out,
        } => {
            let signer_sk = match load_signing_key_file(&signer_key, "--signer-key") {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let mut roots = Vec::new();
            if let Some(ref rf) = roots_file {
                let raw = match fs::read_to_string(rf) {
                    Ok(s) => s,
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: cannot read --roots-file {}: {err}",
                            rf.display()
                        );
                        exit(2);
                    }
                };
                let parsed_arr: Vec<Value> = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: invalid JSON array in --roots-file {}: {err}",
                            rf.display()
                        );
                        exit(2);
                    }
                };
                for (i, item) in parsed_arr.iter().enumerate() {
                    let s = serde_json::to_string(item).unwrap();
                    match parse_flexible_root_json(&s, &format!("--roots-file[{i}]")) {
                        Ok(r) => roots.push(r),
                        Err(err) => {
                            eprintln!("r5e-endpoint-helper: {err}");
                            exit(2);
                        }
                    }
                }
            }
            for spec in &root_keys {
                match parse_root_key_spec(spec, "--root-key") {
                    Ok(r) => roots.push(r),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }
            for spec in &additional_roots {
                match parse_root_key_spec(spec, "--additional-root") {
                    Ok(r) => roots.push(r),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }

            let mut parsed_custodians = Vec::with_capacity(custodians.len());
            for c_spec in &custodians {
                match parse_custodian_spec(c_spec) {
                    Ok(c) => parsed_custodians.push(c),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                }
            }

            let custom_def_blobs = match load_custom_definition_blob(
                roots_changed_definition_file.as_deref(),
                roots_changed_schema_ref.as_deref(),
                "--roots-changed-definition-file",
            ) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let mut all_recovery_keys = recovery_keys;
            let mut pending_recovery_writes: Vec<(&PathBuf, [u8; 32], String)> =
                Vec::with_capacity(generate_recovery_keys.len());
            for rec_path in &generate_recovery_keys {
                if !force && rec_path.exists() {
                    eprintln!(
                        "r5e-endpoint-helper: refusing to overwrite existing private key file {} (pass --force to overwrite)",
                        rec_path.display()
                    );
                    exit(2);
                }
                let seed = match generate_os_random_seed_32() {
                    Ok(s) => s,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };
                let sk = SigningKey::from_bytes(&seed);
                let kid = ed25519_key_id(&sk.verifying_key().to_bytes());
                all_recovery_keys.push(kid.clone());
                pending_recovery_writes.push((rec_path, seed, kid));
            }

            if all_recovery_keys.is_empty() && parsed_custodians.is_empty() {
                eprintln!(
                    "WARNING: Proposed RootsChanged declares neither recoveryKeys nor custodians; no subsequent root rotation will be possible after this change."
                );
            }

            let auth_mode: RootChangeAuthorization = authorization.into();
            let mut params = ProposeRootChangeParams::new(
                deployment.clone(),
                chain.clone(),
                replaces,
                seq,
                auth_mode,
                roots,
                threshold,
            );
            params.recovery_keys = all_recovery_keys.clone();
            params.custodians = parsed_custodians;
            params.reason = reason;
            params.actor = actor;
            params.roots_changed_schema_ref = roots_changed_schema_ref;
            params.approval_schema_ref = approval_schema_ref;
            params.custom_definition_blobs = custom_def_blobs;

            let proposal = match propose_root_change(&signer_sk, &params) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let mut generated_recovery_meta = Vec::with_capacity(pending_recovery_writes.len());
            for (rec_path, seed, kid) in &pending_recovery_writes {
                if let Err(err) = write_private_key_file_0600(rec_path, seed, force) {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(1);
                }
                generated_recovery_meta.push(json!({
                    "keyId": kid,
                    "path": rec_path.to_string_lossy(),
                }));
            }

            let proposal_val = serde_json::to_value(&proposal).expect("serialize proposal");
            let proposal_bytes =
                encode_canonical_json(&proposal_val).expect("canonical proposal JSON");
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(err) = fs::create_dir_all(parent) {
                        eprintln!(
                            "r5e-endpoint-helper: cannot create parent dir for {}: {err}",
                            out.display()
                        );
                        exit(1);
                    }
                }
            }
            if let Err(err) = fs::write(&out, &proposal_bytes) {
                eprintln!(
                    "r5e-endpoint-helper: cannot write proposal {}: {err}",
                    out.display()
                );
                exit(1);
            }

            let signer_key_id = ed25519_key_id(&signer_sk.verifying_key().to_bytes());
            let mut summary = json!({
                "ok": true,
                "deployment": deployment,
                "chain": chain,
                "seq": seq,
                "authorization": auth_mode.as_str(),
                "signer": signer_key_id,
                "changeRef": proposal.change.record_ref,
                "recoveryKeys": all_recovery_keys,
                "proposalPath": out.to_string_lossy(),
            });
            if !generated_recovery_meta.is_empty() {
                let obj = summary.as_object_mut().unwrap();
                obj.insert(
                    "generatedRecoveryKeys".to_string(),
                    json!(&generated_recovery_meta),
                );
                if generated_recovery_meta.len() == 1 {
                    obj.insert(
                        "generatedRecoveryKey".to_string(),
                        generated_recovery_meta[0].clone(),
                    );
                }
            }
            let summary_bytes = encode_canonical_json(&summary).expect("canonical summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::ApproveRootChange {
            proposal,
            root_key,
            custodian,
            custodian_key,
            reason,
            actor,
            approval_schema_ref,
            approval_definition_file,
            out,
        } => {
            let raw_prop = match fs::read_to_string(&proposal) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "r5e-endpoint-helper: cannot read --proposal {}: {err}",
                        proposal.display()
                    );
                    exit(2);
                }
            };
            let mut prop_obj: RootChangeProposalFile = match serde_json::from_str(&raw_prop) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!(
                        "r5e-endpoint-helper: invalid JSON in --proposal {}: {err}",
                        proposal.display()
                    );
                    exit(2);
                }
            };

            let root_sk = match load_signing_key_file(&root_key, "--root-key") {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };
            let cust_sk = match load_signing_key_file(&custodian_key, "--custodian-key") {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let custom_def_blobs = match load_custom_definition_blob(
                approval_definition_file.as_deref(),
                approval_schema_ref.as_deref(),
                "--approval-definition-file",
            ) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let mut params = ApproveRootChangeParams::new(custodian.clone());
            params.reason = reason;
            params.actor = actor;
            params.approval_schema_ref = approval_schema_ref;
            params.custom_definition_blobs = custom_def_blobs;

            let approval_rec = match approve_root_change(&mut prop_obj, &root_sk, &cust_sk, &params)
            {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let dest_path = out.as_ref().unwrap_or(&proposal);
            let updated_val = serde_json::to_value(&prop_obj).expect("serialize updated proposal");
            let updated_bytes =
                encode_canonical_json(&updated_val).expect("canonical updated proposal");
            if let Some(parent) = dest_path.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(err) = fs::create_dir_all(parent) {
                        eprintln!(
                            "r5e-endpoint-helper: cannot create parent dir for {}: {err}",
                            dest_path.display()
                        );
                        exit(1);
                    }
                }
            }
            if let Err(err) = fs::write(dest_path, &updated_bytes) {
                eprintln!(
                    "r5e-endpoint-helper: cannot write updated proposal {}: {err}",
                    dest_path.display()
                );
                exit(1);
            }

            let root_key_id = ed25519_key_id(&root_sk.verifying_key().to_bytes());
            let cust_key_id = ed25519_key_id(&cust_sk.verifying_key().to_bytes());
            let summary = encode_canonical_json(&json!({
                "ok": true,
                "changeRef": prop_obj.change.record_ref,
                "approvalRef": approval_rec.record_ref,
                "root": root_key_id,
                "custodian": custodian,
                "custodianKey": cust_key_id,
                "approvalCount": prop_obj.approvals.len(),
                "proposalPath": dest_path.to_string_lossy(),
            }))
            .expect("canonical approval summary");
            println!("{}", String::from_utf8_lossy(&summary));
        }
        Commands::ApplyRootChange {
            gateway_url,
            proposal,
            grant_gateway_with,
            grant_file,
            gateway_key_id,
            grant_not_before,
            grant_ttl_seconds,
            grant_seq,
            grant_previous,
            grant_actor,
            grant_kinds,
        } => {
            if grant_gateway_with.is_some() && grant_file.is_some() {
                eprintln!(
                    "r5e-endpoint-helper: apply-root-change accepts at most one of --grant-gateway-with or --grant-file"
                );
                exit(2);
            }
            let raw_prop = match fs::read_to_string(&proposal) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!(
                        "r5e-endpoint-helper: cannot read --proposal {}: {err}",
                        proposal.display()
                    );
                    exit(2);
                }
            };
            let prop_obj: RootChangeProposalFile = match serde_json::from_str(&raw_prop) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!(
                        "r5e-endpoint-helper: invalid JSON in --proposal {}: {err}",
                        proposal.display()
                    );
                    exit(2);
                }
            };

            let cfg = ClaimClientConfig::new(gateway_url);
            if let Some(ref gf_path) = grant_file {
                let raw_grant = match fs::read_to_string(gf_path) {
                    Ok(s) => s,
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: cannot read --grant-file {}: {err}",
                            gf_path.display()
                        );
                        exit(2);
                    }
                };
                let parsed_grant: SubmitGrantsRequest = match serde_json::from_str(&raw_grant) {
                    Ok(g) => g,
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: invalid SubmitGrantsRequest JSON in --grant-file {}: {err}",
                            gf_path.display()
                        );
                        exit(2);
                    }
                };
                let (roots_resp, grant_resp) = match apply_root_change_with_grant_request(
                    &cfg,
                    &prop_obj,
                    Some(&parsed_grant),
                ) {
                    Ok(pair) => pair,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: apply-root-change failed: {err}");
                        exit(1);
                    }
                };
                let endorsement_ref = parsed_grant.records.first().map(|r| r.record_ref.clone());
                let grant_root_id = parsed_grant.keys.first().map(|k| k.keyid.clone());
                let summary = encode_canonical_json(&json!({
                    "ok": true,
                    "deployment": prop_obj.deployment,
                    "chain": prop_obj.chain,
                    "seq": prop_obj.seq,
                    "changeRef": prop_obj.change.record_ref,
                    "approvalCount": prop_obj.approvals.len(),
                    "rootsStatus": roots_resp.status,
                    "recordedRefs": roots_resp.recorded_refs,
                    "gatewayGrantSubmitted": grant_resp.is_some(),
                    "grantRootKeyId": grant_root_id,
                    "endorsementRef": endorsement_ref,
                }))
                .expect("canonical apply summary");
                println!("{}", String::from_utf8_lossy(&summary));
                return;
            }

            let grant_sk = match grant_gateway_with {
                Some(ref key_path) => {
                    match load_signing_key_file(key_path, "--grant-gateway-with") {
                        Ok(k) => Some(k),
                        Err(err) => {
                            eprintln!("r5e-endpoint-helper: {err}");
                            exit(2);
                        }
                    }
                }
                None => None,
            };

            let outcome = match apply_root_change(
                &cfg,
                &prop_obj,
                grant_sk.as_ref(),
                gateway_key_id,
                grant_not_before,
                grant_ttl_seconds,
                grant_seq,
                grant_previous,
                &grant_actor,
                grant_kinds,
            ) {
                Ok(o) => o,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: apply-root-change failed: {err}");
                    exit(1);
                }
            };

            let endorsement_ref = outcome
                .gateway_grant
                .as_ref()
                .map(|(built, _)| built.endorsement.record_ref.clone());
            let grant_root_id = outcome
                .gateway_grant
                .as_ref()
                .map(|(built, _)| built.root_key_id.clone());
            let summary = encode_canonical_json(&json!({
                "ok": true,
                "deployment": prop_obj.deployment,
                "chain": prop_obj.chain,
                "seq": prop_obj.seq,
                "changeRef": prop_obj.change.record_ref,
                "approvalCount": prop_obj.approvals.len(),
                "rootsStatus": outcome.roots_response.status,
                "recordedRefs": outcome.roots_response.recorded_refs,
                "gatewayGrantSubmitted": outcome.gateway_grant.is_some(),
                "grantRootKeyId": grant_root_id,
                "endorsementRef": endorsement_ref,
            }))
            .expect("canonical apply summary");
            println!("{}", String::from_utf8_lossy(&summary));
        }
        Commands::GrantReleaser {
            gateway_url,
            deployment,
            stream_prefix,
            root_key_file,
            root_seed_env,
            releaser_pubkey_file,
            releaser_key_file,
            releaser_key_id,
            kinds,
            actor_prefixes,
            acts_for,
            actor,
            grant_token,
            seq,
            previous,
            not_before,
            ttl_seconds,
            out_grant_file,
            submit,
        } => {
            if submit && gateway_url.is_none() {
                eprintln!(
                    "r5e-endpoint-helper: grant-releaser --submit requires --gateway-url <url>"
                );
                exit(2);
            }

            let root_signing_key = match resolve_root_signing_key(
                root_key_file.as_deref(),
                &root_seed_env,
                None,
                false,
                false,
            ) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let resolved_releaser_key_id = match resolve_releaser_key_id(
                releaser_pubkey_file.as_deref(),
                releaser_key_file.as_deref(),
                releaser_key_id.as_deref(),
            ) {
                Ok(kid) => kid,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let cfg_opt = gateway_url.as_deref().map(ClaimClientConfig::new);
            let fetched_status = match &cfg_opt {
                Some(cfg) => match get_deployment_status_raw(cfg) {
                    Ok(pair) => Some(pair),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: GET /v1/deployment failed: {err}");
                        exit(1);
                    }
                },
                None => None,
            };

            let resolved_dep_or_prefix = if let Some(dep) = deployment {
                dep
            } else if let Some(sp) = stream_prefix {
                sp
            } else if let Some(dep) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.deployment.clone())
            {
                dep
            } else if let Some(sp) = fetched_status
                .as_ref()
                .and_then(|(s, _)| s.stream_prefix.clone())
            {
                sp
            } else {
                eprintln!(
                    "r5e-endpoint-helper: could not determine deployment; pass --gateway-url <url>, --deployment <slug>, or --stream-prefix <prefix>"
                );
                exit(2);
            };

            let start_head_floor = fetched_status.as_ref().and_then(|(s, raw)| {
                latest_status_captured_at_utc(raw).or_else(|| {
                    s.deployment_record
                        .as_ref()
                        .and_then(record_captured_at_utc)
                })
            });

            let mut params =
                ReleaserGrantParams::new(resolved_releaser_key_id, resolved_dep_or_prefix);
            if let Some(k) = kinds {
                params.kinds = k;
            }
            if !actor_prefixes.is_empty() {
                params.actor_prefixes = Some(actor_prefixes);
            }
            params.acts_for = acts_for;
            params.actor = actor;
            params.grant_token = grant_token;
            params.seq = seq;
            params.previous = previous;
            params.not_before_override = not_before;
            params.start_head_floor = start_head_floor;
            params.ttl_seconds = ttl_seconds;

            let built = match build_releaser_grant(&root_signing_key, &params) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: invalid releaser grant parameters: {err}");
                    exit(2);
                }
            };

            let grant_bytes = encode_canonical_json(
                &serde_json::to_value(&built.request).expect("serialize releaser grant request"),
            )
            .expect("canonical releaser grant JSON");

            if let Some(parent) = out_grant_file.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(err) = fs::create_dir_all(parent) {
                        eprintln!(
                            "r5e-endpoint-helper: cannot create parent dir for {}: {err}",
                            out_grant_file.display()
                        );
                        exit(1);
                    }
                }
            }
            if let Err(err) = fs::write(&out_grant_file, &grant_bytes) {
                eprintln!(
                    "r5e-endpoint-helper: cannot write --out-grant-file {}: {err}",
                    out_grant_file.display()
                );
                exit(1);
            }

            let mut summary = json!({
                "ok": true,
                "deployment": built.deployment,
                "rootKeyId": built.root_key_id,
                "releaserKeyId": built.releaser_key_id,
                "grantStream": built.grant_stream,
                "retentionStream": built.retention_stream,
                "seq": seq,
                "capturedAt": built.captured_at,
                "notBefore": built.not_before,
                "notAfter": built.not_after,
                "endorsementRef": built.endorsement.record_ref,
                "profileRef": built.profile_ref,
                "outGrantFile": out_grant_file.to_string_lossy(),
                "submitted": submit,
            });

            if submit {
                let cfg = cfg_opt.expect("gateway_url checked Some when submit is true");
                let submit_resp = match submit_deployment_grants(&cfg, &built.request) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: POST /v1/deployment/grants failed: {err}");
                        exit(1);
                    }
                };
                let obj = summary.as_object_mut().unwrap();
                obj.insert("status".to_string(), json!(submit_resp.status));
                obj.insert("recordedRefs".to_string(), json!(submit_resp.recorded_refs));
            }

            let summary_bytes =
                encode_canonical_json(&summary).expect("canonical grant-releaser summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::ReleaseHold {
            gateway_url,
            hold,
            reason,
            bearer_token_env,
            bearer_token_file,
            releaser_key_file,
            releaser_seed_env,
            authority_file,
            out_receipt_file,
        } => {
            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };

            let releaser_sk = match resolve_releaser_signing_key(
                releaser_key_file.as_deref(),
                &releaser_seed_env,
            ) {
                Ok(sk) => sk,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let authority = match authority_file {
                Some(ref auth_path) => {
                    let raw = match fs::read_to_string(auth_path) {
                        Ok(s) => s,
                        Err(err) => {
                            eprintln!(
                                "r5e-endpoint-helper: cannot read --authority-file {}: {err}",
                                auth_path.display()
                            );
                            exit(2);
                        }
                    };
                    let parsed: SubmitGrantsRequest = match serde_json::from_str(&raw) {
                        Ok(g) => g,
                        Err(err) => {
                            eprintln!(
                                "r5e-endpoint-helper: invalid JSON in --authority-file {}: {err}",
                                auth_path.display()
                            );
                            exit(2);
                        }
                    };
                    Some(parsed)
                }
                None => None,
            };
            let authority_carried = authority.is_some();

            let cfg = HoldReleaseClientConfig::new(gateway_url, bearer_token);
            let outcome =
                match execute_release_hold_ceremony(&cfg, &releaser_sk, hold, reason, authority) {
                    Ok(o) => o,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: release-hold failed: {err}");
                        exit(1);
                    }
                };

            let mut summary = json!({
                "ok": true,
                "release": outcome.finalized.release,
                "seq": outcome.finalized.seq,
                "hold": outcome.finalized.hold,
                "releasedBy": outcome.inspection.released_by,
                "recorderIssuer": outcome.inspection.recorder_issuer,
                "stream": outcome.inspection.stream,
                "capturedAt": outcome.inspection.captured_at,
                "reason": outcome.inspection.reason,
                "authorityCarried": authority_carried,
            });

            if let Some(ref receipt_path) = out_receipt_file {
                if let Some(parent) = receipt_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(err) = fs::create_dir_all(parent) {
                            eprintln!(
                                "r5e-endpoint-helper: cannot create parent dir for {}: {err}",
                                receipt_path.display()
                            );
                            exit(1);
                        }
                    }
                }
                let receipt_bytes =
                    encode_canonical_json(&summary).expect("canonical hold-release receipt");
                if let Err(err) = fs::write(receipt_path, &receipt_bytes) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot write --out-receipt-file {}: {err}",
                        receipt_path.display()
                    );
                    exit(1);
                }
                summary.as_object_mut().unwrap().insert(
                    "receiptFile".to_string(),
                    Value::String(receipt_path.to_string_lossy().into_owned()),
                );
            }

            let summary_bytes =
                encode_canonical_json(&summary).expect("canonical release-hold summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::EnrolBadge {
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            holder,
            workload,
            purpose,
            ttl_seconds,
            actor_prefixes,
            kinds,
            cedar_policy,
            require_policy_for_tools,
            policy_required_kinds,
            out_state,
            force,
        } => {
            if !force && out_state.exists() {
                eprintln!(
                    "r5e-endpoint-helper: refusing to overwrite existing state file {} (pass --force to overwrite)",
                    out_state.display()
                );
                exit(2);
            }
            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };

            let policy_bytes: Vec<u8> = match cedar_policy {
                Some(ref pf) => match fs::read(pf) {
                    Ok(b) => {
                        let cedar_str = match std::str::from_utf8(&b) {
                            Ok(s) => s,
                            Err(err) => {
                                eprintln!(
                                    "r5e-endpoint-helper: --cedar-policy {} is not valid UTF-8: {err}",
                                    pf.display()
                                );
                                exit(2);
                            }
                        };
                        if let Err(err) =
                            LocalCedarGate::from_cedar_src(cedar_str, Posture::Enforce, false)
                        {
                            eprintln!(
                                "r5e-endpoint-helper: invalid --cedar-policy {}: {err}",
                                pf.display()
                            );
                            exit(2);
                        }
                        b
                    }
                    Err(err) => {
                        eprintln!(
                            "r5e-endpoint-helper: cannot read --cedar-policy {}: {err}",
                            pf.display()
                        );
                        exit(2);
                    }
                },
                None => b"permit(principal, action, resource);\n".to_vec(),
            };

            let seed = match generate_os_random_seed_32() {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: CSPRNG failure: {err}");
                    exit(1);
                }
            };
            let helper_key = SigningKey::from_bytes(&seed);

            let requested_kinds: Vec<String> = if kinds.is_empty() {
                default_workload_badge_kinds()
            } else {
                kinds.iter().map(|k| normalize_workload_kind(k)).collect()
            };
            let mut normalized_policy_req_kinds: Vec<String> = policy_required_kinds
                .iter()
                .map(|k| normalize_workload_kind(k))
                .collect();
            if require_policy_for_tools
                && !normalized_policy_req_kinds
                    .iter()
                    .any(|k| k == "provenance.r5e.io/v2/ToolCall")
            {
                normalized_policy_req_kinds.push("provenance.r5e.io/v2/ToolCall".to_string());
            }
            let requested_actor_prefixes = if actor_prefixes.is_empty() {
                None
            } else {
                Some(actor_prefixes)
            };

            let cfg = EnrolmentClientConfig::new(&gateway_url, Some(bearer_token));
            let enrol_opts = EnrolBadgeOptions {
                purpose: purpose.clone(),
                session_options: EnrolledSessionOptions {
                    retention_override: None,
                    required_payloads: Some(if normalized_policy_req_kinds.is_empty() {
                        "submitted".to_string()
                    } else {
                        "submitted-and-policy-inputs".to_string()
                    }),
                    policy_required_kinds: Some(normalized_policy_req_kinds),
                },
            };

            let (session, _finalized) = match enrol_endpoint_badge_with_options(
                &cfg,
                helper_key,
                &holder,
                workload,
                requested_kinds,
                requested_actor_prefixes,
                ttl_seconds,
                &policy_bytes,
                &enrol_opts,
            ) {
                Ok(res) => res,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: enrol-badge failed: {err}");
                    exit(1);
                }
            };

            let state_doc =
                EnrolledStateFile::from_enrolled_session(&gateway_url, &holder, purpose, &session);
            if let Err(err) = state_doc.save_0600(&out_state, force) {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(1);
            }

            let summary = json!({
                "ok": true,
                "badge_ref": state_doc.badge_ref,
                "subject_key_id": state_doc.subject_key_id,
                "stream_prefix": state_doc.stream_prefix,
                "profile_ref": state_doc.local_profile_ref,
                "deployment_policy_ref": state_doc.deployment_policy_ref,
                "policy_required_kinds": state_doc.capture_profile.policy_required_kinds,
                "retention": state_doc.retention,
                "not_before": state_doc.not_before,
                "not_after": state_doc.not_after,
                "acts_for": state_doc.acts_for,
                "workload": state_doc.workload,
                "actor_prefixes": state_doc.actor_prefixes,
                "granted_kinds": state_doc.granted_kinds,
                "out_state": out_state.to_string_lossy(),
            });
            let summary_bytes =
                encode_canonical_json(&summary).expect("canonical enrol-badge summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::OpenSession {
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            client_session_id,
            purpose,
            workload,
            details_json,
            state,
        } => {
            if let Some(ref cid) = client_session_id {
                if cid.is_empty() || cid.len() > 128 {
                    eprintln!(
                        "r5e-endpoint-helper: --client-session-id must be 1..=128 UTF-8 bytes (got {} bytes)",
                        cid.len()
                    );
                    exit(2);
                }
            }

            let mut loaded_state = match state {
                Some(ref sp) => match EnrolledStateFile::load(sp) {
                    Ok(st) => Some(st),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                },
                None => None,
            };

            let effective_gateway_url = match gateway_url {
                Some(u) => u,
                None => match loaded_state.as_ref() {
                    Some(st) => st.gateway_url.clone(),
                    None => {
                        eprintln!(
                            "r5e-endpoint-helper: open-session requires --gateway-url (or --state)"
                        );
                        exit(2);
                    }
                },
            };

            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };

            let details_map = match details_json {
                Some(ref raw) => match serde_json::from_str::<Value>(raw) {
                    Ok(Value::Object(m)) => Some(m),
                    Ok(_) => {
                        eprintln!("r5e-endpoint-helper: --details-json must be a JSON object");
                        exit(2);
                    }
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: invalid --details-json: {err}");
                        exit(2);
                    }
                },
                None => None,
            };

            let effective_workload =
                workload.or_else(|| loaded_state.as_ref().and_then(|st| st.workload.clone()));
            let effective_purpose =
                purpose.or_else(|| loaded_state.as_ref().and_then(|st| st.purpose.clone()));

            let req = OpenSessionRequest {
                client_session_id,
                purpose: effective_purpose,
                workload: effective_workload,
                details: details_map,
            };
            let opened = match open_session_over_http(&effective_gateway_url, &bearer_token, &req) {
                Ok(o) => o,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: open-session failed: {err}");
                    exit(1);
                }
            };

            if let (Some(ref sp), Some(ref mut st)) = (&state, &mut loaded_state) {
                st.session_urn = Some(opened.session.clone());
                if let Some(ref anchor_ref) = opened.record_ref {
                    st.session_anchor_ref = Some(anchor_ref.clone());
                }
                if let Err(err) = st.save_0600(sp, true) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot update --state {}: {err}",
                        sp.display()
                    );
                    exit(1);
                }
            }

            let out_val = serde_json::to_value(&opened).expect("serialize OpenedSessionResponse");
            let out_bytes = encode_canonical_json(&out_val).expect("canonical open-session JSON");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        }
        Commands::ShipBundle {
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            bundle_dir,
            state,
            only_unshipped,
            omit_payload_blobs,
            authority_file,
        } => {
            if bundle_dir.is_some() == state.is_some() {
                eprintln!(
                    "r5e-endpoint-helper: ship-bundle requires exactly one of --bundle-dir (--bundle) or --state"
                );
                exit(2);
            }
            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };
            let authority = match read_optional_authority_file(authority_file.as_deref()) {
                Ok(a) => a,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            if let Some(ref sp) = state {
                let mut st = match EnrolledStateFile::load(sp) {
                    Ok(s) => s,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };
                let gw_url = gateway_url.unwrap_or_else(|| st.gateway_url.clone());
                let skip_set: std::collections::BTreeSet<String> = if only_unshipped {
                    st.shipped_record_refs.iter().cloned().collect()
                } else {
                    std::collections::BTreeSet::new()
                };
                let ship_req = match build_ship_request_from_recorder(
                    &st.recorder,
                    Some(&st.subject_key_id),
                    &skip_set,
                    !omit_payload_blobs,
                    authority,
                ) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(1);
                    }
                };
                let resp = match ship_records_over_http(&gw_url, &bearer_token, &ship_req) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: ship-bundle failed: {err}");
                        exit(1);
                    }
                };
                for item in &resp.admitted {
                    if !st.shipped_record_refs.iter().any(|r| r == &item.record_ref) {
                        st.shipped_record_refs.push(item.record_ref.clone());
                    }
                }
                if let Err(err) = st.save_0600(sp, true) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot update --state {}: {err}",
                        sp.display()
                    );
                    exit(1);
                }
                let out_val = serde_json::to_value(&resp).expect("serialize ShipRecordsResponse");
                let out_bytes =
                    encode_canonical_json(&out_val).expect("canonical ship-bundle JSON");
                println!("{}", String::from_utf8_lossy(&out_bytes));
            } else if let Some(ref bp) = bundle_dir {
                let Some(gw_url) = gateway_url else {
                    eprintln!(
                        "r5e-endpoint-helper: ship-bundle --bundle-dir requires --gateway-url"
                    );
                    exit(2);
                };
                let ship_req =
                    match load_ship_request_from_bundle_path(bp, !omit_payload_blobs, authority) {
                        Ok(r) => r,
                        Err(err) => {
                            eprintln!("r5e-endpoint-helper: {err}");
                            exit(2);
                        }
                    };
                let resp = match ship_records_over_http(&gw_url, &bearer_token, &ship_req) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: ship-bundle failed: {err}");
                        exit(1);
                    }
                };
                let out_val = serde_json::to_value(&resp).expect("serialize ShipRecordsResponse");
                let out_bytes =
                    encode_canonical_json(&out_val).expect("canonical ship-bundle JSON");
                println!("{}", String::from_utf8_lossy(&out_bytes));
            }
        }
        Commands::RecordEvent {
            state: state_path,
            kind,
            stream_suffix,
            session,
            no_session,
            actor,
            captured_at,
            tool_name,
            input_file,
            input_text,
            output_file,
            output_text,
            media_type,
            call_ref,
            call_id,
            subject_ref,
            policy_ref,
            outcome,
            reason,
            topic,
            summary,
            recipient,
            body_json,
            body_file,
            out_bundle,
            ship,
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            omit_payload_blobs,
            authority_file,
        } => {
            let invoked_as_ship = std::env::args()
                .nth(1)
                .is_some_and(|arg| arg == "record-and-ship");
            let effective_ship = ship || invoked_as_ship;

            let mut st = match EnrolledStateFile::load(&state_path) {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let effective_session = if no_session {
                None
            } else {
                session.or_else(|| st.session_urn.clone())
            };
            let effective_actor = actor.unwrap_or_else(|| st.default_actor());
            let effective_captured_at = captured_at.unwrap_or_else(|| {
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
            });

            let (body_val, content_refs) = match build_cli_workload_record_body(
                &mut st,
                &kind,
                effective_session.as_deref(),
                tool_name.as_deref(),
                input_file.as_deref(),
                input_text.as_deref(),
                output_file.as_deref(),
                output_text.as_deref(),
                &media_type,
                call_ref.as_deref(),
                call_id.as_deref(),
                subject_ref.as_deref(),
                policy_ref.as_deref(),
                outcome.as_deref(),
                reason.as_deref(),
                topic.as_deref(),
                summary.as_deref(),
                recipient.as_deref(),
                body_json.as_deref(),
                body_file.as_deref(),
            ) {
                Ok(res) => res,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };

            let signed = match st.append_workload_record(
                &stream_suffix,
                &kind,
                &effective_actor,
                effective_session.as_deref(),
                &effective_captured_at,
                body_val,
            ) {
                Ok(rec) => rec,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: record-event failed: {err}");
                    exit(1);
                }
            };

            let decoded_payload =
                decode_strict_base64(&signed.envelope.payload).expect("freshly signed payload");
            let parsed_payload: Value =
                serde_json::from_slice(&decoded_payload).expect("freshly signed payload JSON");
            let recorded_stream = parsed_payload["stream"].as_str().unwrap_or("").to_string();
            let recorded_seq = parsed_payload["seq"].as_u64().unwrap_or(0);
            let recorded_kind = parsed_payload["kind"].as_str().unwrap_or("").to_string();

            if let Some(ref bundle_path) = out_bundle {
                let query = json!({
                    "session": effective_session,
                    "badge": st.badge_ref,
                });
                let bundle_bytes = match st.recorder.export_v2_bundle_bytes(query) {
                    Ok(b) => b,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: cannot export bundle: {err}");
                        exit(1);
                    }
                };
                if let Some(parent) = bundle_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = fs::create_dir_all(parent);
                    }
                }
                if let Err(err) = fs::write(bundle_path, &bundle_bytes) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot write --out-bundle {}: {err}",
                        bundle_path.display()
                    );
                    exit(1);
                }
            }

            let mut out_summary = json!({
                "ok": true,
                "record_ref": signed.record_ref,
                "kind": recorded_kind,
                "stream": recorded_stream,
                "seq": recorded_seq,
                "session": effective_session,
                "actor": effective_actor,
                "profile_ref": st.local_profile_ref,
                "content_refs": content_refs,
                "shipped": false,
            });

            if effective_ship {
                let bearer_token =
                    match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                        Ok(tok) => tok,
                        Err(err) => {
                            eprintln!("r5e-endpoint-helper: {err}");
                            exit(2);
                        }
                    };
                let authority = match read_optional_authority_file(authority_file.as_deref()) {
                    Ok(a) => a,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };
                let gw_url = gateway_url.unwrap_or_else(|| st.gateway_url.clone());
                let skip_set: std::collections::BTreeSet<String> =
                    st.shipped_record_refs.iter().cloned().collect();
                let ship_req = match build_ship_request_from_recorder(
                    &st.recorder,
                    Some(&st.subject_key_id),
                    &skip_set,
                    !omit_payload_blobs,
                    authority,
                ) {
                    Ok(r) => r,
                    Err(err) => {
                        // Persist the newly recorded event even if shipping preparation fails.
                        let _ = st.save_0600(&state_path, true);
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(1);
                    }
                };

                let ship_resp = match ship_records_over_http(&gw_url, &bearer_token, &ship_req) {
                    Ok(r) => r,
                    Err(err) => {
                        // Save recorded local stream state so the operator can inspect or retry shipping.
                        let _ = st.save_0600(&state_path, true);
                        eprintln!("r5e-endpoint-helper: POST /v1/evidence/records failed: {err}");
                        exit(1);
                    }
                };

                for item in &ship_resp.admitted {
                    if !st.shipped_record_refs.iter().any(|r| r == &item.record_ref) {
                        st.shipped_record_refs.push(item.record_ref.clone());
                    }
                }
                let obj = out_summary.as_object_mut().unwrap();
                obj.insert("shipped".to_string(), Value::Bool(true));
                obj.insert("http_status".to_string(), json!(ship_resp.http_status));
                obj.insert("admitted".to_string(), json!(ship_resp.admitted));
            }

            if let Err(err) = st.save_0600(&state_path, true) {
                eprintln!(
                    "r5e-endpoint-helper: cannot update --state {}: {err}",
                    state_path.display()
                );
                exit(1);
            }

            let summary_bytes =
                encode_canonical_json(&out_summary).expect("canonical record-event summary");
            println!("{}", String::from_utf8_lossy(&summary_bytes));
        }
        Commands::RevokeBadge {
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            badge,
            state,
            reason,
        } => {
            let loaded_state = match state {
                Some(ref sp) => match EnrolledStateFile::load(sp) {
                    Ok(st) => Some(st),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                },
                None => None,
            };

            let effective_gateway_url = match gateway_url {
                Some(u) => u,
                None => match loaded_state.as_ref() {
                    Some(st) => st.gateway_url.clone(),
                    None => {
                        eprintln!(
                            "r5e-endpoint-helper: revoke-badge requires --gateway-url (or --state)"
                        );
                        exit(2);
                    }
                },
            };

            let effective_badge = match badge {
                Some(b) => b,
                None => match loaded_state.as_ref() {
                    Some(st) => st.badge_ref.clone(),
                    None => {
                        eprintln!(
                            "r5e-endpoint-helper: revoke-badge requires --badge <REF> or --state <FILE>"
                        );
                        exit(2);
                    }
                },
            };

            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };

            let resp_val = match revoke_badge_over_http(
                &effective_gateway_url,
                &bearer_token,
                &effective_badge,
                &reason,
            ) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: revoke-badge failed: {err}");
                    exit(1);
                }
            };

            let out_bytes =
                encode_canonical_json(&resp_val).expect("canonical revoke-badge response JSON");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        }
        Commands::Exec {
            state: state_path,
            cedar_policy,
            posture,
            agent_id,
            session,
            actor,
            stream_suffix,
            offline,
            outbox,
            outbox_key_file,
            ship,
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            authority_file,
            call_id,
            out_bundle,
            argv,
        } => {
            run_exec_subcommand(
                &state_path,
                cedar_policy.as_deref(),
                posture.into(),
                agent_id,
                session,
                actor,
                &stream_suffix,
                offline,
                outbox.as_deref(),
                outbox_key_file.as_deref(),
                ship,
                gateway_url.as_deref(),
                &bearer_token_env,
                bearer_token_file.as_deref(),
                authority_file.as_deref(),
                call_id.as_deref(),
                out_bundle.as_deref(),
                &argv,
            );
        }
        Commands::McpProxy {
            server_id,
            state: state_path,
            cedar_policy,
            posture,
            block_rug_pull,
            agent_id,
            session,
            actor,
            stream_suffix,
            offline,
            outbox,
            outbox_key_file,
            ship,
            gateway_url,
            bearer_token_env,
            bearer_token_file,
            authority_file,
            out_bundle,
            argv,
        } => {
            run_mcp_proxy_subcommand(
                &server_id,
                &state_path,
                cedar_policy.as_deref(),
                posture.into(),
                block_rug_pull,
                agent_id,
                session,
                actor,
                &stream_suffix,
                offline,
                outbox.as_deref(),
                outbox_key_file.as_deref(),
                ship,
                gateway_url.as_deref(),
                &bearer_token_env,
                bearer_token_file.as_deref(),
                authority_file.as_deref(),
                out_bundle.as_deref(),
                &argv,
            );
        }
        Commands::FlushOutbox {
            outbox,
            gateway_url,
            state,
            bearer_token_env,
            bearer_token_file,
            authority_file,
            outbox_key_file,
        } => {
            let outbox_key =
                match resolve_optional_outbox_key(outbox_key_file.as_deref(), OUTBOX_KEY_ENV_VAR) {
                    Ok(k) => k,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };

            let mut loaded_state = match state {
                Some(ref sp) => match EnrolledStateFile::load(sp) {
                    Ok(st) => Some(st),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                },
                None => None,
            };

            let bearer_token =
                match resolve_bearer_token(bearer_token_file.as_deref(), &bearer_token_env) {
                    Ok(tok) => tok,
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: {err}");
                        exit(2);
                    }
                };
            let authority = match read_optional_authority_file(authority_file.as_deref()) {
                Ok(a) => a,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };
            let effective_gateway_url =
                gateway_url.or_else(|| loaded_state.as_ref().map(|st| st.gateway_url.clone()));

            let res = match flush_outbox_over_http_with_key(
                &outbox,
                effective_gateway_url.as_deref(),
                &bearer_token,
                authority,
                outbox_key.as_ref(),
            ) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: flush-outbox failed: {err}");
                    exit(1);
                }
            };

            if let (Some(ref sp), Some(ref mut st)) = (&state, &mut loaded_state) {
                for item in &res.admitted {
                    if (item.status == "admitted" || item.status == "already_admitted")
                        && !st.shipped_record_refs.iter().any(|r| r == &item.record_ref)
                    {
                        st.shipped_record_refs.push(item.record_ref.clone());
                    }
                }
                if let Err(err) = st.save_0600(sp, true) {
                    eprintln!(
                        "r5e-endpoint-helper: cannot update --state {}: {err}",
                        sp.display()
                    );
                    exit(1);
                }
            }

            let summary = json!({
                "ok": true,
                "outbox": outbox.to_string_lossy(),
                "encrypted": outbox_key.is_some(),
                "pending_before": res.pending_before,
                "pending_after": res.pending_after,
                "flushed": res.flushed,
                "http_status": res.http_status,
                "admitted": res.admitted,
            });
            let out_bytes =
                encode_canonical_json(&summary).expect("canonical flush-outbox response JSON");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        }
        Commands::Hook {
            client,
            mode,
            gateway,
            state_dir,
            bearer_token_env,
            bearer_token_file,
            cedar_policy,
            drain,
        } => {
            use r5e_endpoint_helper::agent_hooks::{
                default_hook_state_dir, drain_conversation, run_hook_invocation, HookClient,
                HookMode, HookRunOptions,
            };
            let resolved_gateway = gateway
                .or_else(|| std::env::var("R5E_GATEWAY_URL").ok())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "http://127.0.0.1:4000".to_string());
            let opts = HookRunOptions {
                client: HookClient::from(client),
                mode: HookMode::from(mode),
                gateway_url: resolved_gateway,
                state_dir: state_dir.unwrap_or_else(default_hook_state_dir),
                bearer_token_env,
                bearer_token_file,
                cedar_policy,
                spawn_drainer: true,
            };
            if let Some(conv_id) = drain {
                let _ = drain_conversation(&conv_id, &opts);
                exit(0);
            }
            let mut stdin_buf = String::new();
            let _ = io::stdin().read_to_string(&mut stdin_buf);
            let out_json = run_hook_invocation(&stdin_buf, &opts);
            println!(
                "{}",
                serde_json::to_string(&out_json).unwrap_or_else(|_| "{}".to_string())
            );
        }
        Commands::InstallHooks {
            client,
            gateway,
            mode,
            path,
            state_dir,
            cedar_policy,
            bearer_token_file,
        } => {
            use r5e_endpoint_helper::agent_hooks::{
                install_hooks_config, HookClient, HookMode, InstallHooksOptions,
            };
            let helper_bin =
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("r5e-endpoint-helper"));
            let opts = InstallHooksOptions {
                client: HookClient::from(client),
                mode: HookMode::from(mode),
                gateway_url: gateway,
                target_dir: path,
                helper_bin,
                state_dir,
                cedar_policy,
                bearer_token_file,
            };
            match install_hooks_config(&opts) {
                Ok(config_path) => {
                    let summary = json!({
                        "ok": true,
                        "client": opts.client.as_str(),
                        "mode": opts.mode.as_str(),
                        "gateway_url": opts.gateway_url,
                        "config_path": config_path.to_string_lossy(),
                        "notice": "Secret redaction is best-effort; tool arguments and outputs are shipped as erasable content blobs to the configured gateway.",
                    });
                    let out_bytes = encode_canonical_json(&summary)
                        .expect("canonical install-hooks response JSON");
                    println!("{}", String::from_utf8_lossy(&out_bytes));
                }
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: install-hooks failed: {err}");
                    exit(1);
                }
            }
        }
        Commands::Status {
            state_dir,
            json: as_json,
        } => {
            use r5e_endpoint_helper::agent_hooks::{
                collect_status_snapshot, default_hook_state_dir, encode_status_json,
            };
            let dir = state_dir.unwrap_or_else(default_hook_state_dir);
            let snapshot = collect_status_snapshot(&dir);
            if as_json {
                match encode_status_json(&snapshot) {
                    Ok(s) => println!("{s}"),
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: status failed: {err}");
                        exit(1);
                    }
                }
            } else {
                println!(
                    "r5e-endpoint-helper v{} | enrolled={} | active_sessions={} | queued_events={} | gateway={}",
                    snapshot.version,
                    snapshot.enrolled,
                    snapshot.active_sessions,
                    snapshot.queued_events,
                    snapshot.gateway_url.as_deref().unwrap_or("(none)")
                );
            }
        }
        Commands::GenerateOutboxKey { out, force } => {
            if let Err(err) = OutboxKey::generate_to_file_0600(&out, force) {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(1);
            }
            let summary = json!({
                "ok": true,
                "out": out.to_string_lossy(),
                "cipher": "chacha20-poly1305",
                "key_bytes": 32,
                "mode": "0600",
            });
            let out_bytes =
                encode_canonical_json(&summary).expect("canonical generate-outbox-key JSON");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        }
        Commands::MintWorkloadBadge {
            root_key_files,
            delegator_key_file,
            workload_key_file,
            generate_workload_key_out,
            workload_public_key,
            workload_algorithm,
            deployment,
            gateway_url,
            gateway_key_id,
            principal,
            workload,
            actor_prefixes,
            holder,
            purpose,
            permitted_kinds,
            policy_file,
            policy_required_kinds,
            require_policy_for_tools,
            retention_disposal,
            keep_content_for_seconds,
            not_before,
            expires_at,
            ttl_seconds,
            may_endorse,
            operator_actor,
            badge_token,
            out_grant_file,
            out_prepared_badge,
            out_badge_pae,
            out_state,
            submit,
            force,
        } => {
            run_mint_workload_badge_subcommand(
                &root_key_files,
                delegator_key_file.as_deref(),
                workload_key_file.as_deref(),
                generate_workload_key_out.as_deref(),
                workload_public_key.as_deref(),
                workload_algorithm.as_deref(),
                deployment.as_deref(),
                gateway_url.as_deref(),
                gateway_key_id,
                principal,
                workload,
                actor_prefixes,
                holder,
                purpose,
                permitted_kinds,
                policy_file.as_deref(),
                &policy_required_kinds,
                require_policy_for_tools,
                retention_disposal.as_deref(),
                keep_content_for_seconds,
                not_before,
                expires_at,
                ttl_seconds,
                may_endorse,
                operator_actor,
                badge_token,
                out_grant_file.as_deref(),
                out_prepared_badge.as_deref(),
                out_badge_pae.as_deref(),
                out_state.as_deref(),
                submit,
                force,
            );
        }
        Commands::CosignWorkloadBadge {
            prepared_badge,
            workload_key_file,
            signature_file,
            signature_b64,
            out_grant_file,
            out_state,
            gateway_url,
            policy_file,
            policy_required_kinds,
            require_policy_for_tools,
            retention_disposal,
            keep_content_for_seconds,
            submit,
            force,
        } => {
            run_cosign_workload_badge_subcommand(
                &prepared_badge,
                workload_key_file.as_deref(),
                signature_file.as_deref(),
                signature_b64.as_deref(),
                out_grant_file.as_deref(),
                out_state.as_deref(),
                gateway_url.as_deref(),
                policy_file.as_deref(),
                &policy_required_kinds,
                require_policy_for_tools,
                retention_disposal.as_deref(),
                keep_content_for_seconds,
                submit,
                force,
            );
        }
        Commands::SubmitGrant {
            gateway_url,
            grant_file,
        } => {
            run_submit_grant_subcommand(&gateway_url, &grant_file);
        }
        Commands::PreparePublication {
            definitions_dir,
            publisher_public_key,
            algorithm,
            name,
            package,
            proposal,
            previous,
            seq,
            manifest_ref,
            stream,
            actor,
            captured_at,
            details_json,
            piv_hardware,
            out_prepared,
            out_pae,
        } => {
            run_prepare_publication_subcommand(
                definitions_dir,
                &publisher_public_key,
                algorithm.as_deref(),
                name,
                package,
                proposal,
                previous,
                seq,
                manifest_ref,
                stream,
                actor,
                captured_at,
                details_json.as_deref(),
                piv_hardware,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizePublication {
            prepared,
            signature_file,
            signature_b64,
            out,
            mode_0600,
        } => {
            run_finalize_publication_subcommand(
                &prepared,
                signature_file.as_deref(),
                signature_b64.as_deref(),
                &out,
                mode_0600,
            );
        }
        Commands::PrepareClaim {
            gateway_url,
            claim_code_file,
            claim_code_env,
            root_public_key,
            algorithm,
            holder,
            custody,
            identity,
            roots_file,
            additional_roots,
            threshold,
            recovery_keys,
            generate_recovery_keys,
            custodians,
            allow_permanent_roots,
            force,
            trusted_publishers,
            allow_untrusted_publisher,
            allow_large_ed25519_pae,
            out_prepared,
            out_pae,
        } => {
            run_prepare_claim_subcommand(
                &gateway_url,
                claim_code_file.as_deref(),
                &claim_code_env,
                &root_public_key,
                algorithm.as_deref(),
                holder,
                custody,
                identity,
                roots_file.as_deref(),
                &additional_roots,
                threshold,
                recovery_keys,
                &generate_recovery_keys,
                &custodians,
                allow_permanent_roots,
                force,
                &trusted_publishers,
                allow_untrusted_publisher,
                allow_large_ed25519_pae,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizeClaim {
            prepared,
            gateway_url,
            claim_code_file,
            claim_code_env,
            signature_file,
            signature_b64,
            out_receipt,
        } => {
            run_finalize_claim_subcommand(
                &prepared,
                gateway_url.as_deref(),
                claim_code_file.as_deref(),
                &claim_code_env,
                signature_file.as_deref(),
                signature_b64.as_deref(),
                out_receipt.as_deref(),
            );
        }
        Commands::PrepareEndorsement {
            issuer_public_key,
            algorithm,
            subject,
            subject_public_key,
            gateway_url,
            deployment,
            stream_prefix,
            grant_token,
            seq,
            previous,
            actor,
            kinds,
            stream_prefixes,
            actor_prefixes,
            omit_actor_prefixes,
            acts_for,
            parent,
            role,
            may_endorse,
            captured_at,
            not_before,
            ttl_seconds,
            sealer_keys,
            details_json,
            allow_large_ed25519_pae,
            out_prepared,
            out_pae,
        } => {
            run_prepare_endorsement_subcommand(
                &issuer_public_key,
                algorithm.as_deref(),
                subject,
                subject_public_key.as_deref(),
                gateway_url.as_deref(),
                deployment,
                stream_prefix,
                grant_token,
                seq,
                previous,
                actor,
                kinds,
                stream_prefixes,
                actor_prefixes,
                omit_actor_prefixes,
                acts_for,
                parent,
                role,
                may_endorse,
                captured_at.as_deref(),
                not_before,
                ttl_seconds,
                sealer_keys,
                details_json.as_deref(),
                allow_large_ed25519_pae,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizeEndorsement {
            prepared,
            signature_file,
            signature_b64,
            with_grant_files,
            out,
            submit,
            gateway_url,
        } => {
            run_finalize_endorsement_subcommand(
                &prepared,
                signature_file.as_deref(),
                signature_b64.as_deref(),
                &with_grant_files,
                &out,
                submit,
                gateway_url.as_deref(),
            );
        }
        Commands::PreparePrincipal {
            public_key,
            algorithm,
            holder,
            custody,
            identity,
            gateway_url,
            deployment,
            stream_prefix,
            actor,
            captured_at,
            sealer_keys,
            details_json,
            allow_large_ed25519_pae,
            out_prepared,
            out_pae,
        } => {
            run_prepare_principal_subcommand(
                &public_key,
                algorithm.as_deref(),
                holder,
                custody,
                identity,
                gateway_url.as_deref(),
                deployment,
                stream_prefix,
                actor,
                captured_at.as_deref(),
                sealer_keys,
                details_json.as_deref(),
                allow_large_ed25519_pae,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizePrincipal {
            prepared,
            signature_file,
            signature_b64,
            out,
        } => {
            run_finalize_principal_subcommand(
                &prepared,
                signature_file.as_deref(),
                signature_b64.as_deref(),
                &out,
            );
        }
        Commands::PrepareRootChange {
            deployment,
            chain,
            replaces,
            seq,
            authorization,
            signer_public_key,
            algorithm,
            root_keys,
            roots_file,
            additional_roots,
            threshold,
            recovery_keys,
            generate_recovery_keys,
            force,
            custodians,
            reason,
            actor,
            captured_at,
            roots_changed_schema_ref,
            approval_schema_ref,
            roots_changed_definition_file,
            allow_large_ed25519_pae,
            out_prepared,
            out_pae,
        } => {
            run_prepare_root_change_subcommand(
                deployment,
                chain,
                replaces,
                seq,
                authorization,
                &signer_public_key,
                algorithm.as_deref(),
                &root_keys,
                roots_file.as_deref(),
                &additional_roots,
                threshold,
                recovery_keys,
                &generate_recovery_keys,
                force,
                &custodians,
                reason,
                actor,
                captured_at.as_deref(),
                roots_changed_schema_ref,
                approval_schema_ref,
                roots_changed_definition_file.as_deref(),
                allow_large_ed25519_pae,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizeRootChange {
            prepared,
            signature_file,
            signature_b64,
            out,
        } => {
            run_finalize_root_change_subcommand(
                &prepared,
                signature_file.as_deref(),
                signature_b64.as_deref(),
                &out,
            );
        }
        Commands::PrepareRootApproval {
            proposal,
            root_public_key,
            root_algorithm,
            custodian,
            custodian_public_key,
            custodian_algorithm,
            reason,
            actor,
            captured_at,
            approval_schema_ref,
            approval_definition_file,
            allow_large_ed25519_pae,
            out_prepared,
            out_pae,
        } => {
            run_prepare_root_approval_subcommand(
                &proposal,
                &root_public_key,
                root_algorithm.as_deref(),
                custodian,
                &custodian_public_key,
                custodian_algorithm.as_deref(),
                reason,
                actor,
                captured_at.as_deref(),
                approval_schema_ref,
                approval_definition_file.as_deref(),
                allow_large_ed25519_pae,
                &out_prepared,
                &out_pae,
            );
        }
        Commands::FinalizeRootApproval {
            proposal,
            prepared,
            root_signature_file,
            root_signature_b64,
            custodian_signature_file,
            custodian_signature_b64,
            out,
        } => {
            run_finalize_root_approval_subcommand(
                &proposal,
                &prepared,
                root_signature_file.as_deref(),
                root_signature_b64.as_deref(),
                custodian_signature_file.as_deref(),
                custodian_signature_b64.as_deref(),
                out.as_deref(),
            );
        }
    }
}

/// Exit status `77` (`EX_NOPERM` in `<sysexits.h>`) returned when `r5e-endpoint-helper exec`
/// blocks a command in `enforce` posture before spawning `<PROGRAM>`.
const EX_NOPERM_EXIT_CODE: i32 = 77;

/// Maximum bytes per child output stream (`stdout` / `stderr`) captured inline into the `ToolResult`
/// content blob; live forwarding to the caller's `stdout` / `stderr` is unbounded.
const MAX_CAPTURED_STREAM_BYTES: usize = 256 * 1024;

fn tee_and_capture_stream<R, W>(mut reader: R, mut writer: W, cap: usize) -> (Vec<u8>, usize, bool)
where
    R: Read,
    W: Write,
{
    let mut captured = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &chunk[..n];
                let _ = writer.write_all(slice);
                let _ = writer.flush();
                total_bytes = total_bytes.saturating_add(n);
                if captured.len() < cap {
                    let remaining = cap - captured.len();
                    if n <= remaining {
                        captured.extend_from_slice(slice);
                    } else {
                        captured.extend_from_slice(&slice[..remaining]);
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (captured, total_bytes, truncated)
}

fn encode_captured_stream_text_or_b64(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), "utf-8"),
        Err(_) => (BASE64_STANDARD.encode(bytes), "base64"),
    }
}

fn write_optional_bundle_export(
    out_bundle: Option<&Path>,
    st: &EnrolledStateFile,
    session_urn: Option<&str>,
) -> Result<(), String> {
    let Some(bundle_path) = out_bundle else {
        return Ok(());
    };
    let query = json!({
        "session": session_urn,
        "badge": st.badge_ref,
    });
    let bundle_bytes = st.recorder.export_v2_bundle_bytes(query)?;
    if let Some(parent) = bundle_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    fs::write(bundle_path, &bundle_bytes)
        .map_err(|e| format!("cannot write --out-bundle {}: {e}", bundle_path.display()))
}

#[allow(clippy::too_many_arguments)]
fn run_exec_subcommand(
    state_path: &Path,
    cedar_policy: Option<&Path>,
    posture: Posture,
    agent_id: Option<String>,
    session: Option<String>,
    actor: Option<String>,
    stream_suffix: &str,
    offline: bool,
    outbox: Option<&Path>,
    outbox_key_file: Option<&Path>,
    ship: bool,
    gateway_url: Option<&str>,
    bearer_token_env: &str,
    bearer_token_file: Option<&Path>,
    authority_file: Option<&Path>,
    call_id: Option<&str>,
    out_bundle: Option<&Path>,
    argv: &[String],
) -> ! {
    let effective_call_id = match call_id {
        Some(cid) => {
            if let Err(err) = validate_call_id(cid, "--call-id") {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
            cid.to_string()
        }
        None => {
            let rnd = generate_os_random_bytes::<8>().unwrap_or([0u8; 8]);
            format!("exec-{}", hex_lower(&rnd))
        }
    };

    let outbox_key = match resolve_optional_outbox_key(outbox_key_file, OUTBOX_KEY_ENV_VAR) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    if let Some(dir) = outbox {
        if let Err(err) = OutboxQueueFile::load_or_empty_with_key(dir, outbox_key.as_ref()) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    }

    let mut st = match EnrolledStateFile::load(state_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let bearer_token = if ship {
        match resolve_bearer_token(bearer_token_file, bearer_token_env) {
            Ok(tok) => Some(tok),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    } else {
        None
    };

    let authority = match read_optional_authority_file(authority_file) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let (cedar_src, _policy_ref) = match st.resolve_and_store_cedar_policy(cedar_policy) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let effective_offline = offline || (outbox.is_some() && !ship);
    let gate = match LocalCedarGate::from_cedar_src(&cedar_src, posture, effective_offline) {
        Ok(g) => g,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let effective_agent_id = agent_id.unwrap_or_else(|| st.holder.clone());
    let effective_session = session.or_else(|| st.session_urn.clone());
    let cedar_session_ctx = effective_session
        .clone()
        .unwrap_or_else(|| format!("{}{}", st.stream_prefix, stream_suffix));
    let effective_actor = actor.unwrap_or_else(|| st.default_actor());

    let program = argv[0].clone();
    let program_args = argv[1..].to_vec();
    let command_line = argv.join(" ");

    let cmd_input_json = json!({
        "program": &program,
        "argv": argv,
        "commandLine": &command_line,
    });
    let cmd_input_bytes =
        encode_canonical_json(&cmd_input_json).expect("canonical exec command input JSON");
    let cmd_input_ref = st
        .recorder
        .put_blob(&cmd_input_bytes, Some("application/json"));
    let input_refs = vec![cmd_input_ref.clone()];

    let action = LocalActionKind::ExecCommand {
        program: program.clone(),
        argv: program_args.clone(),
        command_line: command_line.clone(),
    };
    let verdict = match gate.evaluate(&effective_agent_id, &cedar_session_ctx, &action) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: policy evaluation error: {err}");
            exit(2);
        }
    };

    let target_basename = std::path::Path::new(&program)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&program);

    let t_decision = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let pd_rec = match st.append_policy_decision_record(
        stream_suffix,
        &effective_actor,
        effective_session.as_deref(),
        &t_decision,
        &cmd_input_ref,
        &input_refs,
        &verdict,
        posture,
        "ExecCommand",
        target_basename,
    ) {
        Ok(rec) => rec,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: failed signing PolicyDecision: {err}");
            exit(1);
        }
    };

    // If `Prevented` (`Enforce` + `Deny`): NEVER spawn `<PROGRAM>`!
    if !verdict.allowed_to_execute {
        if let Err(err) =
            write_optional_bundle_export(out_bundle, &st, effective_session.as_deref())
        {
            eprintln!("r5e-endpoint-helper: {err}");
        }
        if let Err(err) = persist_outbox_and_ship_state_with_key(
            &mut st,
            state_path,
            outbox,
            outbox_key.as_ref(),
            ship,
            gateway_url,
            bearer_token.as_deref(),
            authority,
        ) {
            eprintln!("r5e-endpoint-helper: {err}");
        }
        let msg = verdict
            .agent_message
            .as_deref()
            .unwrap_or("Blocked on endpoint by organisation Cedar policy");
        eprintln!("{msg}");
        exit(EX_NOPERM_EXIT_CODE);
    }

    // `Allowed` or `ObservedWouldWithhold`: append `ToolCall` (`policy.decisionRef = pd_rec.record_ref`,
    // top-level `callId` per `A9` §2, flat `Details`) BEFORE spawning `<PROGRAM>`.
    let mut call_details = serde_json::Map::new();
    call_details.insert(
        "program".to_string(),
        Value::String(truncate_utf8_bytes(&program, MAX_DETAILS_VALUE_BYTES)),
    );
    call_details.insert("argc".to_string(), json!(argv.len() as i64));

    let t_call = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let tc_rec = match st.append_gated_tool_call_record(
        stream_suffix,
        &effective_actor,
        effective_session.as_deref(),
        &t_call,
        &program,
        Some(&effective_call_id),
        &cmd_input_ref,
        cmd_input_bytes.len(),
        &input_refs,
        &verdict,
        &pd_rec.record_ref,
        Some(call_details),
    ) {
        Ok(rec) => rec,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: failed signing ToolCall: {err}");
            exit(1);
        }
    };
    if let Err(err) = st.save_0600(state_path, true) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let mut child = match Command::new(&program)
        .args(&program_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(spawn_err) => {
            let err_msg = format!("Failed to spawn {program}: {spawn_err}");
            let result_json = json!({
                "exitCode": 127,
                "spawnError": spawn_err.to_string(),
                "stdout": "",
                "stdoutEncoding": "utf-8",
                "stdoutBytes": 0,
                "stderr": "",
                "stderrEncoding": "utf-8",
                "stderrBytes": 0,
                "truncated": false,
            });
            let result_bytes =
                encode_canonical_json(&result_json).expect("canonical spawn-failure ToolResult");
            let result_ref = st
                .recorder
                .put_blob(&result_bytes, Some("application/json"));
            let mut res_details = serde_json::Map::new();
            res_details.insert("exitCode".to_string(), json!(127_i64));
            res_details.insert("stdoutBytes".to_string(), json!(0_i64));
            res_details.insert("stderrBytes".to_string(), json!(0_i64));
            res_details.insert("truncated".to_string(), Value::Bool(false));
            let t_res = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let _ = st.append_tool_result_record(
                stream_suffix,
                &effective_actor,
                effective_session.as_deref(),
                &t_res,
                &tc_rec.record_ref,
                Some(&effective_call_id),
                &result_ref,
                "application/json",
                result_bytes.len(),
                "failed",
                Some(&err_msg),
                Some(res_details),
            );
            let _ = write_optional_bundle_export(out_bundle, &st, effective_session.as_deref());
            if let Err(ship_err) = persist_outbox_and_ship_state_with_key(
                &mut st,
                state_path,
                outbox,
                outbox_key.as_ref(),
                ship,
                gateway_url,
                bearer_token.as_deref(),
                authority,
            ) {
                eprintln!("r5e-endpoint-helper: {ship_err}");
            }
            eprintln!("r5e-endpoint-helper: failed to execute {program}: {spawn_err}");
            exit(127);
        }
    };

    let child_stdout = child.stdout.take().expect("piped child stdout");
    let child_stderr = child.stderr.take().expect("piped child stderr");

    let out_handle = thread::spawn(move || {
        tee_and_capture_stream(child_stdout, io::stdout(), MAX_CAPTURED_STREAM_BYTES)
    });
    let err_handle = thread::spawn(move || {
        tee_and_capture_stream(child_stderr, io::stderr(), MAX_CAPTURED_STREAM_BYTES)
    });

    let wait_res = child.wait();
    let (stdout_buf, stdout_total, stdout_trunc) =
        out_handle.join().unwrap_or_else(|_| (Vec::new(), 0, false));
    let (stderr_buf, stderr_total, stderr_trunc) =
        err_handle.join().unwrap_or_else(|_| (Vec::new(), 0, false));

    let exit_code_opt = wait_res.as_ref().ok().and_then(|s| s.code());
    let child_exit_code = exit_code_opt.unwrap_or(1);
    let succeeded = wait_res.as_ref().is_ok_and(|s| s.success());

    let (stdout_val, stdout_enc) = encode_captured_stream_text_or_b64(&stdout_buf);
    let (stderr_val, stderr_enc) = encode_captured_stream_text_or_b64(&stderr_buf);
    let result_json = json!({
        "exitCode": exit_code_opt,
        "stdout": stdout_val,
        "stdoutEncoding": stdout_enc,
        "stdoutBytes": stdout_total as i64,
        "stderr": stderr_val,
        "stderrEncoding": stderr_enc,
        "stderrBytes": stderr_total as i64,
        "truncated": stdout_trunc || stderr_trunc,
    });
    let result_bytes = encode_canonical_json(&result_json).expect("canonical ToolResult JSON");
    let result_ref = st
        .recorder
        .put_blob(&result_bytes, Some("application/json"));

    let outcome_str = if succeeded { "completed" } else { "failed" };
    let fail_reason = if succeeded {
        None
    } else {
        Some(format!("Process exited with code {child_exit_code}"))
    };

    let mut res_details = serde_json::Map::new();
    res_details.insert("exitCode".to_string(), json!(child_exit_code as i64));
    res_details.insert("stdoutBytes".to_string(), json!(stdout_total as i64));
    res_details.insert("stderrBytes".to_string(), json!(stderr_total as i64));
    res_details.insert(
        "truncated".to_string(),
        Value::Bool(stdout_trunc || stderr_trunc),
    );

    let t_res = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    if let Err(err) = st.append_tool_result_record(
        stream_suffix,
        &effective_actor,
        effective_session.as_deref(),
        &t_res,
        &tc_rec.record_ref,
        Some(&effective_call_id),
        &result_ref,
        "application/json",
        result_bytes.len(),
        outcome_str,
        fail_reason.as_deref(),
        Some(res_details),
    ) {
        eprintln!("r5e-endpoint-helper: failed signing ToolResult: {err}");
        exit(1);
    }

    if let Err(err) = write_optional_bundle_export(out_bundle, &st, effective_session.as_deref()) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    if let Err(err) = persist_outbox_and_ship_state_with_key(
        &mut st,
        state_path,
        outbox,
        outbox_key.as_ref(),
        ship,
        gateway_url,
        bearer_token.as_deref(),
        authority,
    ) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(if child_exit_code != 0 {
            child_exit_code
        } else {
            1
        });
    }

    exit(child_exit_code);
}

enum McpServerStdoutEvent {
    Line(String),
    Eof,
}

struct PendingMcpToolCall {
    record_ref: String,
    call_id: Option<String>,
    tool_name: String,
}

fn canonical_jsonrpc_id_key(id_val: &Value) -> Option<String> {
    if id_val.is_null() {
        return None;
    }
    encode_canonical_json(id_val)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// Extracts a non-empty `1..=256` UTF-8 byte `callId` from a JSON-RPC 2.0 `"id"` (`A9` §2).
fn extract_jsonrpc_call_id(id_val: Option<&Value>) -> Option<String> {
    let raw = match id_val? {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    if raw.len() <= 256 {
        Some(raw)
    } else {
        use sha2::{Digest, Sha256};
        Some(format!(
            "id-sha256:{}",
            hex_lower(&Sha256::digest(raw.as_bytes()))
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_mcp_server_line(
    resp_line: &str,
    guard: &mut McpStdioSessionGuard,
    pending_tool_calls: &mut HashMap<String, PendingMcpToolCall>,
    st: &mut EnrolledStateFile,
    state_path: &Path,
    stream_suffix: &str,
    effective_actor: &str,
    effective_session: Option<&str>,
    server_id: &str,
    outbox: Option<&Path>,
    outbox_key: Option<&OutboxKey>,
    ship: bool,
    gateway_url: Option<&str>,
    bearer_token: Option<&str>,
    authority: Option<&SubmitGrantsRequest>,
    stdout: &mut io::Stdout,
) -> Option<String> {
    let mut matched_id_key = None;
    let mut dirty = false;

    if let Ok(resp_val) = serde_json::from_str::<Value>(resp_line) {
        if let Some(id_val) = resp_val.get("id") {
            matched_id_key = canonical_jsonrpc_id_key(id_val);
        }

        // 1. Observe `tools/list` responses and append signed `Observation`
        //    (`mcp_tools_pinned` or `mcp_descriptor_rug_pull`).
        if let Some(obs) = guard.observe_server_response(&resp_val) {
            let now_utc = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            match st.append_mcp_descriptor_observation(
                stream_suffix,
                effective_actor,
                effective_session,
                &now_utc,
                server_id,
                &obs,
            ) {
                Ok(_) => {
                    dirty = true;
                }
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: failed signing MCP Observation: {err}");
                }
            }
        }

        // 2. Match pending `tools/call` response by JSON-RPC `id` and append signed `ToolResult`
        //    (never emit `ToolResult` if no `ToolCall` was recorded for this `id`!).
        if let Some(ref key) = matched_id_key {
            if let Some(pending) = pending_tool_calls.remove(key) {
                let resp_canonical = encode_canonical_json(&resp_val)
                    .unwrap_or_else(|_| resp_line.trim_end().as_bytes().to_vec());
                let resp_blob_ref = st
                    .recorder
                    .put_blob(&resp_canonical, Some("application/json"));
                let is_jsonrpc_error = resp_val.get("error").is_some();
                let is_failed = is_jsonrpc_error
                    || resp_val
                        .get("result")
                        .and_then(|r| r.get("isError"))
                        .and_then(Value::as_bool)
                        == Some(true);
                let outcome_str = if is_failed { "failed" } else { "completed" };
                let fail_reason = if is_jsonrpc_error {
                    Some("MCP server returned JSON-RPC error".to_string())
                } else if is_failed {
                    Some("MCP tool returned result.isError = true".to_string())
                } else {
                    None
                };
                let mut res_details = serde_json::Map::new();
                res_details.insert(
                    "serverId".to_string(),
                    Value::String(truncate_utf8_bytes(server_id, MAX_DETAILS_VALUE_BYTES)),
                );
                res_details.insert(
                    "mcpTool".to_string(),
                    Value::String(truncate_utf8_bytes(
                        &pending.tool_name,
                        MAX_DETAILS_VALUE_BYTES,
                    )),
                );
                res_details.insert("jsonrpcError".to_string(), Value::Bool(is_jsonrpc_error));
                let now_utc =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                match st.append_tool_result_record(
                    stream_suffix,
                    effective_actor,
                    effective_session,
                    &now_utc,
                    &pending.record_ref,
                    pending.call_id.as_deref(),
                    &resp_blob_ref,
                    "application/json",
                    resp_canonical.len(),
                    outcome_str,
                    fail_reason.as_deref(),
                    Some(res_details),
                ) {
                    Ok(_) => {
                        dirty = true;
                    }
                    Err(err) => {
                        eprintln!("r5e-endpoint-helper: failed signing MCP ToolResult: {err}");
                    }
                }
            }
        }
    }

    // Forward child MCP frame to harness stdout (preserving trailing newline).
    if resp_line.ends_with('\n') {
        let _ = write!(stdout, "{resp_line}");
    } else {
        let _ = writeln!(stdout, "{resp_line}");
    }
    let _ = stdout.flush();

    if dirty {
        if let Err(err) = persist_outbox_and_ship_state_with_key(
            st,
            state_path,
            outbox,
            outbox_key,
            ship,
            gateway_url,
            bearer_token,
            authority.cloned(),
        ) {
            eprintln!("r5e-endpoint-helper: {err}");
        }
    }

    matched_id_key
}

#[allow(clippy::too_many_arguments)]
fn run_mcp_proxy_subcommand(
    server_id: &str,
    state_path: &Path,
    cedar_policy: Option<&Path>,
    posture: Posture,
    block_rug_pull: bool,
    agent_id: Option<String>,
    session: Option<String>,
    actor: Option<String>,
    stream_suffix: &str,
    offline: bool,
    outbox: Option<&Path>,
    outbox_key_file: Option<&Path>,
    ship: bool,
    gateway_url: Option<&str>,
    bearer_token_env: &str,
    bearer_token_file: Option<&Path>,
    authority_file: Option<&Path>,
    out_bundle: Option<&Path>,
    argv: &[String],
) -> ! {
    let outbox_key = match resolve_optional_outbox_key(outbox_key_file, OUTBOX_KEY_ENV_VAR) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    if let Some(dir) = outbox {
        if let Err(err) = OutboxQueueFile::load_or_empty_with_key(dir, outbox_key.as_ref()) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    }

    let mut st = match EnrolledStateFile::load(state_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let bearer_token = if ship {
        match resolve_bearer_token(bearer_token_file, bearer_token_env) {
            Ok(tok) => Some(tok),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    } else {
        None
    };

    let authority = match read_optional_authority_file(authority_file) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let (cedar_src, _policy_ref) = match st.resolve_and_store_cedar_policy(cedar_policy) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let effective_offline = offline || (outbox.is_some() && !ship);
    let gate = match LocalCedarGate::from_cedar_src(&cedar_src, posture, effective_offline) {
        Ok(g) => g,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let effective_agent_id = agent_id.unwrap_or_else(|| st.holder.clone());
    let effective_session = session.or_else(|| st.session_urn.clone());
    let cedar_session_ctx = effective_session
        .clone()
        .unwrap_or_else(|| format!("{}{}", st.stream_prefix, stream_suffix));
    let effective_actor = actor.unwrap_or_else(|| st.default_actor());

    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|err| {
            eprintln!(
                "r5e-endpoint-helper: failed to spawn MCP server {}: {err}",
                argv[0]
            );
            exit(127);
        });

    let mut child_stdin_opt = child.stdin.take();
    let child_stdout = child.stdout.take().expect("piped MCP child stdout");

    let (srv_tx, srv_rx) = mpsc::channel::<McpServerStdoutEvent>();
    let srv_reader_handle = thread::spawn(move || {
        let mut reader = io::BufReader::new(child_stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let _ = srv_tx.send(McpServerStdoutEvent::Eof);
                    break;
                }
                Ok(_) => {
                    if srv_tx.send(McpServerStdoutEvent::Line(line)).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = srv_tx.send(McpServerStdoutEvent::Eof);
                    break;
                }
            }
        }
    });

    let mut guard = McpStdioSessionGuard::with_rug_pull_quarantine(server_id, block_rug_pull);
    let mut pending_tool_calls: HashMap<String, PendingMcpToolCall> = HashMap::new();
    let mut server_eof = false;

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let raw = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        if raw.trim().is_empty() {
            continue;
        }

        // Drain any unsolicited child stdout frames that arrived before this client line.
        while let Ok(ev) = srv_rx.try_recv() {
            match ev {
                McpServerStdoutEvent::Line(sline) => {
                    let _ = handle_mcp_server_line(
                        &sline,
                        &mut guard,
                        &mut pending_tool_calls,
                        &mut st,
                        state_path,
                        stream_suffix,
                        &effective_actor,
                        effective_session.as_deref(),
                        server_id,
                        outbox,
                        outbox_key.as_ref(),
                        ship,
                        gateway_url,
                        bearer_token.as_deref(),
                        authority.as_ref(),
                        &mut stdout,
                    );
                }
                McpServerStdoutEvent::Eof => {
                    server_eof = true;
                    break;
                }
            }
        }

        let parsed: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: ignoring malformed JSON-RPC frame on stdin: {err}");
                continue;
            }
        };

        let has_method = parsed.get("method").and_then(Value::as_str).is_some();
        let req_id_key = if has_method {
            parsed.get("id").and_then(canonical_jsonrpc_id_key)
        } else {
            None
        };

        let disposition = match guard.inspect_client_request(
            &parsed,
            &effective_agent_id,
            &cedar_session_ctx,
            &gate,
        ) {
            Ok(d) => d,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: MCP gate error: {err}");
                continue;
            }
        };

        match disposition {
            ClientFrameDisposition::InterceptWithResponse {
                verdict,
                tool_name,
                synthetic_response,
            } => {
                // Build canonical `tools/call` input blob so `PolicyDecision.subject` & `inputRefs`
                // are backed by a content-addressed blob in `st.recorder` (`VERIFY-V2` §6.4).
                let args_val = parsed
                    .get("params")
                    .and_then(|p| p.get("arguments"))
                    .filter(|v| !v.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let (args_digest, _) = canonical_tool_arguments_digest(&parsed).unwrap_or_default();
                let call_blob_val = json!({
                    "server_id": server_id,
                    "tool_name": &tool_name,
                    "arguments": args_val,
                    "arguments_sha256": args_digest,
                    "descriptor_sha256": guard.pinned_descriptor_sha256(),
                });
                let call_blob_bytes = encode_canonical_json(&call_blob_val)
                    .expect("canonical intercepted MCP ToolCall input JSON");
                let call_input_ref = st
                    .recorder
                    .put_blob(&call_blob_bytes, Some("application/json"));
                let mut input_refs = vec![call_input_ref.clone()];
                if let Some(pin) = guard.pinned_descriptor_sha256() {
                    if st.recorder.blobs().contains_key(pin) && !input_refs.iter().any(|r| r == pin)
                    {
                        input_refs.push(pin.to_string());
                    }
                }

                let full_tool_label = format!("{server_id}:{tool_name}");
                let now_utc =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                if let Err(err) = st.append_policy_decision_record(
                    stream_suffix,
                    &effective_actor,
                    effective_session.as_deref(),
                    &now_utc,
                    &call_input_ref,
                    &input_refs,
                    &verdict,
                    posture,
                    "InvokeMcpTool",
                    &full_tool_label,
                ) {
                    eprintln!("r5e-endpoint-helper: failed signing MCP PolicyDecision: {err}");
                }

                // Write synthetic response directly to `mcp-proxy` stdout WITHOUT touching child stdin!
                let synth_bytes = encode_canonical_json(&synthetic_response)
                    .unwrap_or_else(|_| synthetic_response.to_string().into_bytes());
                let _ = stdout.write_all(&synth_bytes);
                let _ = stdout.write_all(b"\n");
                let _ = stdout.flush();

                if let Err(err) = persist_outbox_and_ship_state_with_key(
                    &mut st,
                    state_path,
                    outbox,
                    outbox_key.as_ref(),
                    ship,
                    gateway_url,
                    bearer_token.as_deref(),
                    authority.clone(),
                ) {
                    eprintln!("r5e-endpoint-helper: {err}");
                }
            }
            ClientFrameDisposition::Forward { verdict, tool_name } => {
                if let (Some(verdict), Some(tool_name)) = (verdict, tool_name) {
                    let args_val = parsed
                        .get("params")
                        .and_then(|p| p.get("arguments"))
                        .filter(|v| !v.is_null())
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    let (args_digest, _) =
                        canonical_tool_arguments_digest(&parsed).unwrap_or_default();
                    let call_blob_val = json!({
                        "server_id": server_id,
                        "tool_name": &tool_name,
                        "arguments": args_val,
                        "arguments_sha256": args_digest,
                        "descriptor_sha256": guard.pinned_descriptor_sha256(),
                    });
                    let call_blob_bytes = encode_canonical_json(&call_blob_val)
                        .expect("canonical MCP ToolCall input JSON");
                    let call_input_ref = st
                        .recorder
                        .put_blob(&call_blob_bytes, Some("application/json"));
                    let mut input_refs = vec![call_input_ref.clone()];
                    if let Some(pin) = guard.pinned_descriptor_sha256() {
                        if st.recorder.blobs().contains_key(pin)
                            && !input_refs.iter().any(|r| r == pin)
                        {
                            input_refs.push(pin.to_string());
                        }
                    }

                    let full_tool_label = format!("{server_id}:{tool_name}");
                    let t_pd =
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                    let pd_res = st.append_policy_decision_record(
                        stream_suffix,
                        &effective_actor,
                        effective_session.as_deref(),
                        &t_pd,
                        &call_input_ref,
                        &input_refs,
                        &verdict,
                        posture,
                        "InvokeMcpTool",
                        &full_tool_label,
                    );
                    match pd_res {
                        Ok(pd_rec) => {
                            let call_id = extract_jsonrpc_call_id(parsed.get("id"));
                            let mut call_details = serde_json::Map::new();
                            call_details.insert(
                                "serverId".to_string(),
                                Value::String(truncate_utf8_bytes(
                                    server_id,
                                    MAX_DETAILS_VALUE_BYTES,
                                )),
                            );
                            call_details.insert(
                                "mcpTool".to_string(),
                                Value::String(truncate_utf8_bytes(
                                    &tool_name,
                                    MAX_DETAILS_VALUE_BYTES,
                                )),
                            );
                            let t_tc = chrono::Utc::now()
                                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                            match st.append_gated_tool_call_record(
                                stream_suffix,
                                &effective_actor,
                                effective_session.as_deref(),
                                &t_tc,
                                &full_tool_label,
                                call_id.as_deref(),
                                &call_input_ref,
                                call_blob_bytes.len(),
                                &input_refs,
                                &verdict,
                                &pd_rec.record_ref,
                                Some(call_details),
                            ) {
                                Ok(tc_rec) => {
                                    if let Some(ref id_key) = req_id_key {
                                        pending_tool_calls.insert(
                                            id_key.clone(),
                                            PendingMcpToolCall {
                                                record_ref: tc_rec.record_ref,
                                                call_id,
                                                tool_name,
                                            },
                                        );
                                    }
                                    let _ = st.save_0600(state_path, true);
                                }
                                Err(err) => {
                                    eprintln!(
                                        "r5e-endpoint-helper: failed signing MCP ToolCall: {err}"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "r5e-endpoint-helper: failed signing MCP PolicyDecision: {err}"
                            );
                        }
                    }
                }

                // Forward JSON-RPC frame to child MCP server stdin:
                let Some(ref mut cstdin) = child_stdin_opt else {
                    break;
                };
                if writeln!(cstdin, "{raw}").is_err() || cstdin.flush().is_err() {
                    break;
                }

                // If this frame was a JSON-RPC request (`method` + `id`), wait for the child's
                // matching response `id` so `tools/list` pinning / rug-pull detection and
                // `ToolResult` recording complete in strict causal order before the next request!
                if let Some(ref expected_key) = req_id_key {
                    while !server_eof {
                        match srv_rx.recv() {
                            Ok(McpServerStdoutEvent::Line(sline)) => {
                                let got_key = handle_mcp_server_line(
                                    &sline,
                                    &mut guard,
                                    &mut pending_tool_calls,
                                    &mut st,
                                    state_path,
                                    stream_suffix,
                                    &effective_actor,
                                    effective_session.as_deref(),
                                    server_id,
                                    outbox,
                                    outbox_key.as_ref(),
                                    ship,
                                    gateway_url,
                                    bearer_token.as_deref(),
                                    authority.as_ref(),
                                    &mut stdout,
                                );
                                if got_key.as_deref() == Some(expected_key.as_str()) {
                                    break;
                                }
                            }
                            Ok(McpServerStdoutEvent::Eof) | Err(_) => {
                                server_eof = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if server_eof {
            break;
        }
    }

    // Close child stdin so a well-behaved stdio MCP server exits cleanly after flushing any
    // remaining buffered output, then drain `srv_rx` with a bounded timeout.
    drop(child_stdin_opt);
    if !server_eof {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match srv_rx.recv_timeout(remaining) {
                Ok(McpServerStdoutEvent::Line(sline)) => {
                    let _ = handle_mcp_server_line(
                        &sline,
                        &mut guard,
                        &mut pending_tool_calls,
                        &mut st,
                        state_path,
                        stream_suffix,
                        &effective_actor,
                        effective_session.as_deref(),
                        server_id,
                        outbox,
                        outbox_key.as_ref(),
                        ship,
                        gateway_url,
                        bearer_token.as_deref(),
                        authority.as_ref(),
                        &mut stdout,
                    );
                }
                Ok(McpServerStdoutEvent::Eof) | Err(_) => break,
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = srv_reader_handle.join();

    if let Err(err) = write_optional_bundle_export(out_bundle, &st, effective_session.as_deref()) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = persist_outbox_and_ship_state_with_key(
        &mut st,
        state_path,
        outbox,
        outbox_key.as_ref(),
        ship,
        gateway_url,
        bearer_token.as_deref(),
        authority,
    ) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    exit(0);
}

fn read_optional_authority_file(
    path: Option<&Path>,
) -> Result<Option<SubmitGrantsRequest>, String> {
    let Some(auth_path) = path else {
        return Ok(None);
    };
    let raw = fs::read_to_string(auth_path)
        .map_err(|e| format!("cannot read --authority-file {}: {e}", auth_path.display()))?;
    let parsed: SubmitGrantsRequest = serde_json::from_str(&raw).map_err(|e| {
        format!(
            "invalid JSON in --authority-file {}: {e}",
            auth_path.display()
        )
    })?;
    Ok(Some(parsed))
}

#[allow(clippy::too_many_arguments)]
fn build_cli_workload_record_body(
    st: &mut EnrolledStateFile,
    kind_arg: &str,
    effective_session: Option<&str>,
    tool_name: Option<&str>,
    input_file: Option<&Path>,
    input_text: Option<&str>,
    output_file: Option<&Path>,
    output_text: Option<&str>,
    media_type: &str,
    call_ref: Option<&str>,
    call_id: Option<&str>,
    subject_ref: Option<&str>,
    policy_ref: Option<&str>,
    outcome: Option<&str>,
    reason: Option<&str>,
    topic: Option<&str>,
    summary: Option<&str>,
    recipient: Option<&str>,
    body_json: Option<&str>,
    body_file: Option<&Path>,
) -> Result<(Value, Vec<String>), String> {
    let mut content_refs = Vec::new();

    let mut store_payload = |file_opt: Option<&Path>,
                             text_opt: Option<&str>|
     -> Result<Option<(String, usize)>, String> {
        if let Some(p) = file_opt {
            let bytes = fs::read(p)
                .map_err(|e| format!("cannot read payload file {}: {e}", p.display()))?;
            let bref = st.recorder.put_blob(&bytes, Some(media_type));
            if !content_refs.contains(&bref) {
                content_refs.push(bref.clone());
            }
            Ok(Some((bref, bytes.len())))
        } else if let Some(txt) = text_opt {
            let bytes = txt.as_bytes();
            let bref = st.recorder.put_blob(bytes, Some(media_type));
            if !content_refs.contains(&bref) {
                content_refs.push(bref.clone());
            }
            Ok(Some((bref, bytes.len())))
        } else {
            Ok(None)
        }
    };

    let input_stored = store_payload(input_file, input_text)?;
    let output_stored = store_payload(output_file, output_text)?;

    if let Some(raw_json) = body_json {
        let val: Value =
            serde_json::from_str(raw_json).map_err(|e| format!("invalid --body-json: {e}"))?;
        if !val.is_object() {
            return Err("--body-json must be a JSON object".to_string());
        }
        return Ok((val, content_refs));
    }
    if let Some(bf) = body_file {
        let raw = fs::read_to_string(bf)
            .map_err(|e| format!("cannot read --body-file {}: {e}", bf.display()))?;
        let val: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid JSON in --body-file {}: {e}", bf.display()))?;
        if !val.is_object() {
            return Err("--body-file must contain a JSON object".to_string());
        }
        return Ok((val, content_refs));
    }

    let short_kind = kind_arg
        .strip_prefix("provenance.r5e.io/v2/")
        .unwrap_or(kind_arg);

    let body = match short_kind {
        "ToolCall" => {
            let (cref, size) = match input_stored {
                Some(pair) => pair,
                None => {
                    let default_bytes = b"{}";
                    let bref = st.recorder.put_blob(default_bytes, Some(media_type));
                    if !content_refs.contains(&bref) {
                        content_refs.push(bref.clone());
                    }
                    (bref, default_bytes.len())
                }
            };
            let mut m = serde_json::Map::new();
            m.insert(
                "tool".to_string(),
                Value::String(tool_name.unwrap_or("cli-tool").to_string()),
            );
            if let Some(cid) = call_id {
                validate_call_id(cid, "--call-id")?;
                m.insert("callId".to_string(), Value::String(cid.to_string()));
            }
            m.insert("contentRef".to_string(), Value::String(cref));
            m.insert(
                "mediaType".to_string(),
                Value::String(media_type.to_string()),
            );
            m.insert("size".to_string(), json!(size));
            if let Some(s) = summary {
                if !s.is_empty() {
                    m.insert("summary".to_string(), Value::String(s.to_string()));
                }
            }
            Value::Object(m)
        }
        "ToolResult" => {
            let required_call = call_ref.ok_or_else(|| {
                "ToolResult requires --call-ref <evidence:sha256:...> referencing an admitted ToolCall record (A9 §2)".to_string()
            })?;
            let (cref, size) = match output_stored.or(input_stored) {
                Some(pair) => pair,
                None => {
                    let default_bytes = b"{}";
                    let bref = st.recorder.put_blob(default_bytes, Some(media_type));
                    if !content_refs.contains(&bref) {
                        content_refs.push(bref.clone());
                    }
                    (bref, default_bytes.len())
                }
            };
            let mut m = serde_json::Map::new();
            m.insert("call".to_string(), Value::String(required_call.to_string()));
            if let Some(cid) = call_id {
                validate_call_id(cid, "--call-id")?;
                m.insert("callId".to_string(), Value::String(cid.to_string()));
            }
            m.insert("contentRef".to_string(), Value::String(cref));
            m.insert(
                "mediaType".to_string(),
                Value::String(media_type.to_string()),
            );
            m.insert("size".to_string(), json!(size));
            m.insert(
                "outcome".to_string(),
                Value::String(outcome.unwrap_or("completed").to_string()),
            );
            if let Some(r) = reason {
                if !r.is_empty() {
                    m.insert("reason".to_string(), Value::String(r.to_string()));
                }
            }
            if let Some(s) = summary {
                if !s.is_empty() {
                    m.insert("summary".to_string(), Value::String(s.to_string()));
                }
            }
            Value::Object(m)
        }
        "PolicyDecision" => {
            let (subj_ref, input_refs) = if let Some(sr) = subject_ref.or(call_ref) {
                let mut irefs = Vec::new();
                if let Some((in_ref, _)) = input_stored {
                    irefs.push(in_ref);
                } else {
                    irefs.push(sr.to_string());
                }
                (sr.to_string(), irefs)
            } else {
                let (in_ref, _) = match input_stored {
                    Some(pair) => pair,
                    None => {
                        let default_bytes = b"{}";
                        let bref = st.recorder.put_blob(default_bytes, Some(media_type));
                        if !content_refs.contains(&bref) {
                            content_refs.push(bref.clone());
                        }
                        (bref, default_bytes.len())
                    }
                };
                (in_ref.clone(), vec![in_ref])
            };
            let pref = policy_ref.unwrap_or(&st.deployment_policy_ref);
            let mut eval = serde_json::Map::new();
            eval.insert("policyRef".to_string(), Value::String(pref.to_string()));
            eval.insert(
                "outcome".to_string(),
                Value::String(outcome.unwrap_or("allow").to_string()),
            );
            eval.insert("inputRefs".to_string(), json!(input_refs));
            if let Some(r) = reason {
                if !r.is_empty() {
                    eval.insert("reason".to_string(), Value::String(r.to_string()));
                }
            }
            json!({
                "subject": subj_ref,
                "evaluation": Value::Object(eval),
            })
        }
        "Observation" => {
            let mut crefs = Vec::new();
            if let Some((in_ref, _)) = input_stored {
                crefs.push(in_ref);
            }
            if let Some((out_ref, _)) = output_stored {
                if !crefs.contains(&out_ref) {
                    crefs.push(out_ref);
                }
            }
            json!({
                "topic": topic.unwrap_or("endpoint.observation"),
                "contentRefs": crefs,
            })
        }
        "SessionOpened" => {
            let sess = effective_session.ok_or_else(|| {
                "SessionOpened requires --session <URN> (or bound session in --state)".to_string()
            })?;
            json!({
                "session": sess,
            })
        }
        "SessionClosed" => {
            let sess = effective_session.ok_or_else(|| {
                "SessionClosed requires --session <URN> (or bound session in --state)".to_string()
            })?;
            let through: Vec<Value> = st
                .recorder
                .stream_heads()
                .iter()
                .filter(|(stream, _)| stream.starts_with(&st.stream_prefix))
                .map(|(stream, (seq, event))| {
                    json!({
                        "stream": stream,
                        "seq": seq,
                        "event": event,
                    })
                })
                .collect();
            let mut m = serde_json::Map::new();
            m.insert("session".to_string(), Value::String(sess.to_string()));
            m.insert(
                "outcome".to_string(),
                Value::String(outcome.unwrap_or("completed").to_string()),
            );
            m.insert("through".to_string(), Value::Array(through));
            if let Some(r) = reason {
                if !r.is_empty() {
                    m.insert("reason".to_string(), Value::String(r.to_string()));
                }
            }
            Value::Object(m)
        }
        "Disclosure" => {
            let mut provided = Vec::new();
            if let Some((in_ref, _)) = input_stored {
                provided.push(in_ref);
            }
            if let Some((out_ref, _)) = output_stored {
                if !provided.contains(&out_ref) {
                    provided.push(out_ref);
                }
            }
            let mut m = serde_json::Map::new();
            m.insert("requestedRefs".to_string(), json!(provided));
            m.insert("providedRefs".to_string(), json!(provided));
            m.insert(
                "recipient".to_string(),
                Value::String(recipient.unwrap_or("urn:r5e:recipient:auditor").to_string()),
            );
            m.insert(
                "outcome".to_string(),
                Value::String(outcome.unwrap_or("provided").to_string()),
            );
            if let Some(r) = reason {
                if !r.is_empty() {
                    m.insert("reason".to_string(), Value::String(r.to_string()));
                }
            }
            Value::Object(m)
        }
        "Verification" => {
            let (report_ref, _) = match output_stored.or(input_stored) {
                Some(pair) => pair,
                None => {
                    let default_bytes = b"{\"ok\":true}";
                    let bref = st
                        .recorder
                        .put_blob(default_bytes, Some("application/json"));
                    if !content_refs.contains(&bref) {
                        content_refs.push(bref.clone());
                    }
                    (bref, default_bytes.len())
                }
            };
            let target = subject_ref
                .or(call_ref)
                .unwrap_or(&st.badge_ref)
                .to_string();
            json!({
                "targetRefs": [target],
                "verifierRef": st.local_profile_ref,
                "reportRef": report_ref,
                "outcome": outcome.unwrap_or("valid"),
            })
        }
        other => {
            return Err(format!(
                "kind {other:?} requires explicit --body-json or --body-file"
            ));
        }
    };

    Ok((body, content_refs))
}

fn load_public_key_file_or_inline(raw_arg: &str, flag_label: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw_arg.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag_label} must be non-empty"));
    }
    let as_path = Path::new(trimmed);
    if as_path.exists() {
        fs::read(as_path)
            .map_err(|e| format!("cannot read {flag_label} {}: {e}", as_path.display()))
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

fn parse_workload_public_key_with_alg(
    raw_arg: &str,
    alg_hint: Option<&str>,
) -> Result<(SignatureAlgorithm, Vec<u8>), String> {
    let expected_alg = match alg_hint {
        Some(a) => Some(SignatureAlgorithm::parse(a)?),
        None => None,
    };
    let raw_bytes = load_public_key_file_or_inline(raw_arg, "--workload-public-key")?;
    let (alg, pub_bytes, _) =
        parse_public_key_material(expected_alg, &raw_bytes, "--workload-public-key")?;
    Ok((alg, pub_bytes))
}

fn load_and_validate_cedar_policy(policy_file: Option<&Path>) -> Result<Vec<u8>, String> {
    match policy_file {
        Some(pf) => {
            let bytes = fs::read(pf)
                .map_err(|e| format!("cannot read --policy-file {}: {e}", pf.display()))?;
            let cedar_str = std::str::from_utf8(&bytes)
                .map_err(|e| format!("--policy-file {} must be UTF-8: {e}", pf.display()))?;
            LocalCedarGate::from_cedar_src(cedar_str, Posture::Enforce, false)
                .map_err(|e| format!("invalid --policy-file {}: {e}", pf.display()))?;
            Ok(bytes)
        }
        None => Ok(DEFAULT_OFFLINE_CEDAR_POLICY.as_bytes().to_vec()),
    }
}

fn resolve_offline_retention_override(
    retention_disposal: Option<&str>,
    keep_content_for_seconds: Option<u64>,
    status_raw: Option<&Value>,
) -> Result<Option<Option<Value>>, String> {
    if let Some(mode_raw) = retention_disposal {
        let mode = mode_raw.trim();
        return match mode {
            "never" => {
                if keep_content_for_seconds.is_some() {
                    return Err(
                        "--keep-content-for-seconds cannot be combined with --retention-disposal never"
                            .to_string(),
                    );
                }
                Ok(Some(Some(json!({"disposal": "never"}))))
            }
            "by-record" => {
                let secs = keep_content_for_seconds.ok_or_else(|| {
                    "--retention-disposal by-record requires --keep-content-for-seconds <SECONDS>"
                        .to_string()
                })?;
                if secs == 0 {
                    return Err("--keep-content-for-seconds must be >= 1".to_string());
                }
                Ok(Some(Some(json!({
                    "disposal": "by-record",
                    "keepContentForSeconds": secs,
                }))))
            }
            other => Err(format!(
                "invalid --retention-disposal {other:?}: expected \"never\" or \"by-record\""
            )),
        };
    }

    if let Some(secs) = keep_content_for_seconds {
        if secs == 0 {
            return Err("--keep-content-for-seconds must be >= 1".to_string());
        }
        return Ok(Some(Some(json!({
            "disposal": "by-record",
            "keepContentForSeconds": secs,
        }))));
    }

    if let Some(raw) = status_raw {
        if let Some(ret) = raw.get("retention") {
            if !ret.is_null() {
                return Ok(Some(Some(ret.clone())));
            }
        }
    }

    Ok(None)
}

fn build_offline_session_options(
    policy_required_kinds: &[String],
    require_policy_for_tools: bool,
    retention_override: Option<Option<Value>>,
) -> EnrolledSessionOptions {
    let mut normalized_policy_req_kinds: Vec<String> = policy_required_kinds
        .iter()
        .map(|k| normalize_workload_kind(k))
        .collect();
    if require_policy_for_tools
        && !normalized_policy_req_kinds
            .iter()
            .any(|k| k == "provenance.r5e.io/v2/ToolCall")
    {
        normalized_policy_req_kinds.push("provenance.r5e.io/v2/ToolCall".to_string());
    }
    let required_payloads = if normalized_policy_req_kinds.is_empty() {
        "submitted".to_string()
    } else {
        "submitted-and-policy-inputs".to_string()
    };
    EnrolledSessionOptions {
        retention_override,
        policy_required_kinds: Some(normalized_policy_req_kinds),
        required_payloads: Some(required_payloads),
    }
}

fn write_json_output_file(path: &Path, val: &Value, label: &str) -> Result<(), String> {
    let bytes = encode_canonical_json(val)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create parent directory for {label}: {e}"))?;
        }
    }
    fs::write(path, &bytes).map_err(|e| format!("cannot write {label} {}: {e}", path.display()))
}

#[allow(clippy::too_many_arguments)]
fn run_mint_workload_badge_subcommand(
    root_key_files: &[PathBuf],
    delegator_key_file: Option<&Path>,
    workload_key_file: Option<&Path>,
    generate_workload_key_out: Option<&Path>,
    workload_public_key: Option<&str>,
    workload_algorithm: Option<&str>,
    deployment: Option<&str>,
    gateway_url: Option<&str>,
    gateway_key_id: Option<String>,
    principal: String,
    workload: String,
    actor_prefixes: Vec<String>,
    holder: String,
    purpose: Option<String>,
    permitted_kinds: Vec<String>,
    policy_file: Option<&Path>,
    policy_required_kinds: &[String],
    require_policy_for_tools: bool,
    retention_disposal: Option<&str>,
    keep_content_for_seconds: Option<u64>,
    not_before: Option<String>,
    expires_at: Option<String>,
    ttl_seconds: Option<u64>,
    may_endorse: bool,
    operator_actor: String,
    badge_token: Option<String>,
    out_grant_file: Option<&Path>,
    out_prepared_badge: Option<&Path>,
    out_badge_pae: Option<&Path>,
    out_state: Option<&Path>,
    submit: bool,
    force: bool,
) {
    let mode_count = usize::from(workload_key_file.is_some())
        + usize::from(generate_workload_key_out.is_some())
        + usize::from(workload_public_key.is_some());
    if mode_count != 1 {
        eprintln!(
            "r5e-endpoint-helper: mint-workload-badge requires exactly one of --workload-key-file, --generate-workload-key-out, or --workload-public-key"
        );
        exit(2);
    }

    if workload_public_key.is_some() {
        if out_state.is_some() || submit || out_grant_file.is_some() {
            eprintln!(
                "r5e-endpoint-helper: --workload-public-key prepares a 1-signature draft (--out-prepared-badge); run cosign-workload-badge with the workload private key or detached signature to produce --out-grant-file / --out-state or --submit"
            );
            exit(2);
        }
    } else if out_prepared_badge.is_some() || out_badge_pae.is_some() {
        eprintln!(
            "r5e-endpoint-helper: --out-prepared-badge / --out-badge-pae are only used with --workload-public-key (2-step air-gapped co-sign)"
        );
        exit(2);
    }

    if submit && gateway_url.is_none() {
        eprintln!("r5e-endpoint-helper: --submit requires --gateway-url <URL>");
        exit(2);
    }

    let mut root_keys = Vec::with_capacity(root_key_files.len());
    for rkf in root_key_files {
        match load_signing_key_file(rkf, "--root-key-file") {
            Ok(sk) => root_keys.push(sk),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    let explicit_delegator_key = match delegator_key_file {
        Some(dkf) => match load_signing_key_file(dkf, "--delegator-key-file") {
            Ok(sk) => Some(sk),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        },
        None => None,
    };

    // Optional `GET /v1/deployment` status query when `--gateway-url` is provided (best-effort if
    // `--deployment` is already explicit and `--submit` is false; mandatory when needed).
    let fetched_status = match gateway_url {
        Some(gw_url) => {
            let cfg = ClaimClientConfig::new(gw_url);
            match get_deployment_status_raw(&cfg) {
                Ok(pair) => Some(pair),
                Err(err) => {
                    if deployment.is_none() || submit {
                        eprintln!("r5e-endpoint-helper: GET {gw_url}/v1/deployment failed: {err}");
                        exit(1);
                    }
                    None
                }
            }
        }
        None => None,
    };

    let resolved_deployment = if let Some(dep) = deployment {
        dep.to_string()
    } else if let Some(dep) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.deployment.clone())
    {
        dep
    } else if let Some(sp) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.stream_prefix.clone())
    {
        sp
    } else {
        eprintln!(
            "r5e-endpoint-helper: could not determine deployment; pass --deployment <slug> or reachable --gateway-url <url>"
        );
        exit(2);
    };

    let start_head_floor = fetched_status.as_ref().and_then(|(s, raw)| {
        latest_status_captured_at_utc(raw).or_else(|| {
            s.deployment_record
                .as_ref()
                .and_then(record_captured_at_utc)
        })
    });
    let resolved_gw_key_id = gateway_key_id.or_else(|| {
        fetched_status
            .as_ref()
            .and_then(|(s, _)| s.gateway_key.as_ref().map(|k| k.keyid.clone()))
    });

    let mut params = OfflineWorkloadBadgeParams::new(resolved_deployment, principal, workload);
    params.extra_actor_prefixes = actor_prefixes;
    params.holder = holder;
    params.purpose = purpose;
    params.kinds = permitted_kinds;
    params.may_endorse = may_endorse;
    params.operator_actor = operator_actor;
    params.badge_token_hex = badge_token;
    params.start_head_floor = start_head_floor;
    params.not_before = not_before;
    params.expires_at = expires_at;
    params.ttl_seconds = ttl_seconds;
    params.gateway_key_id = resolved_gw_key_id;

    // Validate policy & retention options upfront before generating or writing any keys/files.
    let policy_bytes = match load_and_validate_cedar_policy(policy_file) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    let retention_override = match resolve_offline_retention_override(
        retention_disposal,
        keep_content_for_seconds,
        fetched_status.as_ref().map(|(_, raw)| raw),
    ) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    // Branch A: 2-step air-gapped `--workload-public-key` mode.
    if let Some(pub_arg) = workload_public_key {
        let (workload_alg, pub_bytes) =
            match parse_workload_public_key_with_alg(pub_arg, workload_algorithm) {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            };
        let prepared = match prepare_offline_workload_badge_with_alg(
            &root_keys,
            explicit_delegator_key.as_ref(),
            workload_alg,
            &pub_bytes,
            &params,
        ) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: mint-workload-badge failed: {err}");
                exit(2);
            }
        };
        if let Some(pae_path) = out_badge_pae {
            let pae_bytes = match prepared.badge_pae_bytes() {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(1);
                }
            };
            if let Err(err) = write_atomic_file(pae_path, &pae_bytes, 0o644) {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(1);
            }
        }
        let prep_val =
            serde_json::to_value(&prepared).expect("serialize PreparedOfflineWorkloadBadge");
        if let Some(out_prep) = out_prepared_badge {
            if let Err(err) = write_json_output_file(out_prep, &prep_val, "--out-prepared-badge") {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(1);
            }
            let mut summary = json!({
                "ok": true,
                "mode": "prepared",
                "deployment": prepared.deployment,
                "workload_key_id": prepared.workload_key_id,
                "workload_algorithm": prepared.workload_algorithm,
                "badge_issuer_key_id": prepared.badge_issuer_key_id,
                "ephemeral_delegator": prepared.ephemeral_delegator,
                "delegator_key_id": prepared.delegator_key_id,
                "stream_prefix": prepared.stream_prefix,
                "badge_stream": prepared.badge_stream,
                "principal": prepared.principal,
                "workload": prepared.workload,
                "actor_prefixes": prepared.actor_prefixes,
                "kinds": prepared.kinds,
                "not_before": prepared.not_before,
                "not_after": prepared.not_after,
                "out_prepared_badge": out_prep.to_string_lossy(),
            });
            if let Some(pae_path) = out_badge_pae {
                summary["out_badge_pae"] = Value::String(pae_path.to_string_lossy().into_owned());
            }
            if prepared.ephemeral_delegator {
                summary["revocation_note"] =
                    Value::String(EPHEMERAL_DELEGATOR_REVOCATION_NOTE.to_string());
            }
            let out_bytes =
                encode_canonical_json(&summary).expect("canonical prepared-badge summary");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        } else {
            let out_bytes =
                encode_canonical_json(&prep_val).expect("canonical PreparedOfflineWorkloadBadge");
            println!("{}", String::from_utf8_lossy(&out_bytes));
        }
        return;
    }

    // Branch B: 1-step co-signing with `--workload-key-file` or `--generate-workload-key-out`.
    let workload_sk = if let Some(wkf) = workload_key_file {
        match load_signing_key_file(wkf, "--workload-key-file") {
            Ok(sk) => sk,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    } else if let Some(gen_out) = generate_workload_key_out {
        let seed = match generate_os_random_seed_32() {
            Ok(s) => s,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: CSPRNG failure: {err}");
                exit(1);
            }
        };
        if let Err(err) = write_private_key_file_0600(gen_out, &seed, force) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
        SigningKey::from_bytes(&seed)
    } else {
        unreachable!("validated mode_count == 1")
    };

    let minted = match mint_offline_workload_badge(
        &root_keys,
        explicit_delegator_key.as_ref(),
        &workload_sk,
        &params,
    ) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: mint-workload-badge failed: {err}");
            exit(2);
        }
    };

    let grant_val =
        serde_json::to_value(&minted.grant_request).expect("serialize SubmitGrantsRequest");
    if let Some(out_grant) = out_grant_file {
        if let Err(err) = write_json_output_file(out_grant, &grant_val, "--out-grant-file") {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
    }

    let mut state_summary_fields: Option<Value> = None;
    if let Some(state_path) = out_state {
        let sess_opts = build_offline_session_options(
            policy_required_kinds,
            require_policy_for_tools,
            retention_override,
        );
        let eff_gw = gateway_url.unwrap_or("http://127.0.0.1:4000");
        let st_doc = match minted.build_enrolled_state_file(
            eff_gw,
            workload_sk,
            &policy_bytes,
            &sess_opts,
        ) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: failed building --out-state: {err}");
                exit(1);
            }
        };
        if let Err(err) = st_doc.save_0600(state_path, force) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
        state_summary_fields = Some(json!({
            "out_state": state_path.to_string_lossy(),
            "local_profile_ref": st_doc.local_profile_ref,
            "deployment_policy_ref": st_doc.deployment_policy_ref,
            "retention": st_doc.retention,
        }));
    }

    let submit_summary = if submit {
        let gw_url = gateway_url.expect("validated submit requires gateway_url");
        let cfg = ClaimClientConfig::new(gw_url);
        match submit_deployment_grants(&cfg, &minted.grant_request) {
            Ok(resp) => Some(json!({
                "status": resp.status,
                "recorded_refs": resp.recorded_refs,
                "badge": resp.raw.get("badge"),
                "sealed": resp.raw.get("sealed"),
            })),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: POST /v1/deployment/grants failed: {err}");
                exit(1);
            }
        }
    } else {
        None
    };

    if out_grant_file.is_none() && out_state.is_none() && !submit {
        // When no output path or `--submit` was passed, emit the pure `SubmitGrantsRequest` JSON on stdout
        // so operators can pipe directly or inspect `{records, keys, blobs}` cleanly.
        let out_bytes = encode_canonical_json(&grant_val).expect("canonical SubmitGrantsRequest");
        println!("{}", String::from_utf8_lossy(&out_bytes));
        return;
    }

    let mut summary = json!({
        "ok": true,
        "badge_ref": minted.badge_ref,
        "workload_key_id": minted.workload_key_id,
        "badge_issuer_key_id": minted.badge_issuer_key_id,
        "root_key_ids": minted.root_key_ids,
        "ephemeral_delegator": minted.ephemeral_delegator,
        "delegator_key_id": minted.delegator_key_id,
        "deployment": minted.deployment,
        "stream_prefix": minted.stream_prefix,
        "badge_stream": minted.badge_stream,
        "principal": minted.principal,
        "workload": minted.workload,
        "actor_prefixes": minted.actor_prefixes,
        "kinds": minted.kinds,
        "captured_at": minted.captured_at,
        "not_before": minted.not_before,
        "not_after": minted.not_after,
        "record_refs": minted.grant_request.records.iter().map(|r| &r.record_ref).collect::<Vec<_>>(),
    });
    if minted.ephemeral_delegator {
        summary["revocation_note"] = Value::String(EPHEMERAL_DELEGATOR_REVOCATION_NOTE.to_string());
    }
    if let Some(out_grant) = out_grant_file {
        summary["out_grant_file"] = Value::String(out_grant.to_string_lossy().into_owned());
    }
    if let Some(st_val) = state_summary_fields {
        summary["state"] = st_val;
    }
    if let Some(sub_val) = submit_summary {
        summary["submitted"] = sub_val;
    }
    let out_bytes = encode_canonical_json(&summary).expect("canonical mint-workload-badge summary");
    println!("{}", String::from_utf8_lossy(&out_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_cosign_workload_badge_subcommand(
    prepared_badge_path: &Path,
    workload_key_file: Option<&Path>,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    out_grant_file: Option<&Path>,
    out_state: Option<&Path>,
    gateway_url: Option<&str>,
    policy_file: Option<&Path>,
    policy_required_kinds: &[String],
    require_policy_for_tools: bool,
    retention_disposal: Option<&str>,
    keep_content_for_seconds: Option<u64>,
    submit: bool,
    force: bool,
) {
    let sig_modes = usize::from(workload_key_file.is_some())
        + usize::from(signature_file.is_some())
        + usize::from(signature_b64.is_some());
    if sig_modes != 1 {
        eprintln!(
            "r5e-endpoint-helper: cosign-workload-badge requires exactly one of --workload-key-file, --signature-file, or --signature-b64"
        );
        exit(2);
    }
    if out_state.is_some() && workload_key_file.is_none() {
        eprintln!(
            "r5e-endpoint-helper: --out-state embeds a local Ed25519 workload seed and requires --workload-key-file"
        );
        exit(2);
    }
    if submit && gateway_url.is_none() {
        eprintln!("r5e-endpoint-helper: --submit requires --gateway-url <URL>");
        exit(2);
    }

    let raw_prep = match fs::read_to_string(prepared_badge_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared-badge {}: {err}",
                prepared_badge_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedOfflineWorkloadBadge = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared-badge {}: {err}",
                prepared_badge_path.display()
            );
            exit(2);
        }
    };

    let workload_sk_opt = match workload_key_file {
        Some(wkf) => match load_signing_key_file(wkf, "--workload-key-file") {
            Ok(sk) => Some(sk),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        },
        None => None,
    };

    let policy_bytes = match load_and_validate_cedar_policy(policy_file) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    let fetched_status = match gateway_url {
        Some(gw_url) if out_state.is_some() && retention_disposal.is_none() => {
            let cfg = ClaimClientConfig::new(gw_url);
            get_deployment_status_raw(&cfg).ok()
        }
        _ => None,
    };
    let retention_override = match resolve_offline_retention_override(
        retention_disposal,
        keep_content_for_seconds,
        fetched_status.as_ref().map(|(_, raw)| raw),
    ) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let (minted, sig_normalized) = if let Some(ref workload_sk) = workload_sk_opt {
        match cosign_prepared_offline_workload_badge(&prepared, workload_sk) {
            Ok(m) => (m, false),
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cosign-workload-badge refused prepared draft: {err}"
                );
                exit(2);
            }
        }
    } else if let Some(sf) = signature_file {
        let raw_sig = match fs::read(sf) {
            Ok(b) => b,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cannot read --signature-file {}: {err}",
                    sf.display()
                );
                exit(2);
            }
        };
        match cosign_prepared_offline_workload_badge_with_external_signature(
            &prepared, &raw_sig, false,
        ) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cosign-workload-badge refused external signature: {err}"
                );
                exit(2);
            }
        }
    } else if let Some(sb64) = signature_b64 {
        match cosign_prepared_offline_workload_badge_with_external_signature(
            &prepared,
            sb64.as_bytes(),
            true,
        ) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cosign-workload-badge refused external signature: {err}"
                );
                exit(2);
            }
        }
    } else {
        unreachable!("validated sig_modes == 1")
    };

    let grant_val =
        serde_json::to_value(&minted.grant_request).expect("serialize SubmitGrantsRequest");
    if let Some(out_grant) = out_grant_file {
        if let Err(err) = write_json_output_file(out_grant, &grant_val, "--out-grant-file") {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
    }

    let mut state_summary_fields: Option<Value> = None;
    if let Some(state_path) = out_state {
        let workload_sk = workload_sk_opt.expect("validated out_state requires workload_key_file");
        let sess_opts = build_offline_session_options(
            policy_required_kinds,
            require_policy_for_tools,
            retention_override,
        );
        let eff_gw = gateway_url.unwrap_or("http://127.0.0.1:4000");
        let st_doc = match minted.build_enrolled_state_file(
            eff_gw,
            workload_sk,
            &policy_bytes,
            &sess_opts,
        ) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: failed building --out-state: {err}");
                exit(1);
            }
        };
        if let Err(err) = st_doc.save_0600(state_path, force) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
        state_summary_fields = Some(json!({
            "out_state": state_path.to_string_lossy(),
            "local_profile_ref": st_doc.local_profile_ref,
            "deployment_policy_ref": st_doc.deployment_policy_ref,
            "retention": st_doc.retention,
        }));
    }

    let submit_summary = if submit {
        let gw_url = gateway_url.expect("validated submit requires gateway_url");
        let cfg = ClaimClientConfig::new(gw_url);
        match submit_deployment_grants(&cfg, &minted.grant_request) {
            Ok(resp) => Some(json!({
                "status": resp.status,
                "recorded_refs": resp.recorded_refs,
                "badge": resp.raw.get("badge"),
                "sealed": resp.raw.get("sealed"),
            })),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: POST /v1/deployment/grants failed: {err}");
                exit(1);
            }
        }
    } else {
        None
    };

    if out_grant_file.is_none() && out_state.is_none() && !submit {
        let out_bytes = encode_canonical_json(&grant_val).expect("canonical SubmitGrantsRequest");
        println!("{}", String::from_utf8_lossy(&out_bytes));
        return;
    }

    let mut summary = json!({
        "ok": true,
        "badge_ref": minted.badge_ref,
        "workload_key_id": minted.workload_key_id,
        "badge_issuer_key_id": minted.badge_issuer_key_id,
        "signature_normalized": sig_normalized,
        "deployment": minted.deployment,
        "stream_prefix": minted.stream_prefix,
        "badge_stream": minted.badge_stream,
        "principal": minted.principal,
        "workload": minted.workload,
        "actor_prefixes": minted.actor_prefixes,
        "kinds": minted.kinds,
        "not_before": minted.not_before,
        "not_after": minted.not_after,
        "record_refs": minted.grant_request.records.iter().map(|r| &r.record_ref).collect::<Vec<_>>(),
    });
    if let Some(out_grant) = out_grant_file {
        summary["out_grant_file"] = Value::String(out_grant.to_string_lossy().into_owned());
    }
    if let Some(st_val) = state_summary_fields {
        summary["state"] = st_val;
    }
    if let Some(sub_val) = submit_summary {
        summary["submitted"] = sub_val;
    }
    let out_bytes =
        encode_canonical_json(&summary).expect("canonical cosign-workload-badge summary");
    println!("{}", String::from_utf8_lossy(&out_bytes));
}

fn run_submit_grant_subcommand(gateway_url: &str, grant_file: &Path) {
    let raw = match fs::read_to_string(grant_file) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --grant-file {}: {err}",
                grant_file.display()
            );
            exit(2);
        }
    };
    let req: SubmitGrantsRequest = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid SubmitGrantsRequest JSON in {}: {err}",
                grant_file.display()
            );
            exit(2);
        }
    };
    if req.records.is_empty() {
        eprintln!(
            "r5e-endpoint-helper: --grant-file {} contains zero records",
            grant_file.display()
        );
        exit(2);
    }

    let cfg = ClaimClientConfig::new(gateway_url);
    let resp = match submit_deployment_grants(&cfg, &req) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: submit-grant failed: {err}");
            exit(1);
        }
    };

    let out = json!({
        "ok": true,
        "status": resp.status,
        "recorded_refs": resp.recorded_refs,
        "badge": resp.raw.get("badge"),
        "sealed": resp.raw.get("sealed"),
        "raw": resp.raw,
    });
    let out_bytes = encode_canonical_json(&out).expect("canonical submit-grant JSON");
    println!("{}", String::from_utf8_lossy(&out_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_publication_subcommand(
    definitions_dir: Option<PathBuf>,
    publisher_public_key: &str,
    algorithm: Option<&str>,
    name: String,
    package: Option<String>,
    proposal: Option<String>,
    previous: Option<String>,
    seq: Option<u64>,
    manifest_ref: Option<String>,
    stream: Option<String>,
    actor: Option<String>,
    captured_at: Option<String>,
    details_json: Option<&str>,
    piv_hardware: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    let resolved_defs_dir = definitions_dir
        .or_else(|| std::env::var_os("R5E_DEFINITIONS_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("definitions"));

    let parsed_alg = match algorithm {
        Some(raw) => match SignatureAlgorithm::parse(raw) {
            Ok(a) => Some(a),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        },
        None => None,
    };

    let pub_key_raw =
        match load_public_key_file_or_inline(publisher_public_key, "--publisher-public-key") {
            Ok(b) => b,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let details_map = match details_json {
        Some(raw) => match serde_json::from_str::<Value>(raw) {
            Ok(Value::Object(m)) => Some(m),
            Ok(_) => {
                eprintln!("r5e-endpoint-helper: --details-json must be a JSON object");
                exit(2);
            }
            Err(err) => {
                eprintln!("r5e-endpoint-helper: invalid --details-json: {err}");
                exit(2);
            }
        },
        None => None,
    };

    let effective_captured_at = captured_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true));

    let params = PreparePublicationParams {
        definitions_dir: resolved_defs_dir,
        publisher_public_key_raw: pub_key_raw,
        algorithm: parsed_alg,
        publisher_name: name,
        package,
        proposal,
        previous,
        envelope_seq: seq,
        manifest_ref,
        stream,
        actor,
        captured_at: effective_captured_at,
        details: details_map,
    };

    let (prepared, pae_bytes) = match prepare_publication_with_piv_guard(&params, piv_hardware) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: prepare-publication failed: {err}");
            exit(2);
        }
    };

    if !piv_hardware
        && prepared.publisher_public_key.algorithm == "ed25519"
        && pae_bytes.len() > PIV_HARDWARE_ED25519_MAX_PAE_BYTES
    {
        if let Err(warn_msg) =
            check_piv_ed25519_pae_limit(SignatureAlgorithm::Ed25519, pae_bytes.len())
        {
            eprintln!("WARNING: {warn_msg}");
        }
    }

    let prep_val = serde_json::to_value(&prepared).expect("serialize PreparedPublication");
    let prep_bytes = encode_canonical_json(&prep_val).expect("canonical PreparedPublication JSON");
    if let Err(err) = write_atomic_file(out_prepared, &prep_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "record_ref": prepared.record_ref,
        "publisher_key_id": prepared.publisher_public_key.keyid,
        "algorithm": prepared.publisher_public_key.algorithm,
        "profile_ref": prepared.profile_ref,
        "definition_count": prepared.blobs.len().saturating_sub(1),
        "pae_bytes": pae_bytes.len(),
        "pae_sha256": prepared.pae_sha256,
        "out_prepared": out_prepared.to_string_lossy(),
        "out_pae": out_pae.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical prepare-publication summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_publication_subcommand(
    prepared_path: &Path,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    out_path: &Path,
    mode_0600: bool,
) {
    if signature_file.is_some() == signature_b64.is_some() {
        eprintln!(
            "r5e-endpoint-helper: finalize-publication requires exactly one of --signature-file or --signature-b64"
        );
        exit(2);
    }

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedPublication = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let (sig_bytes, is_b64_flag) = if let Some(sf) = signature_file {
        match fs::read(sf) {
            Ok(b) => (b, false),
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cannot read --signature-file {}: {err}",
                    sf.display()
                );
                exit(2);
            }
        }
    } else if let Some(sb64) = signature_b64 {
        (sb64.as_bytes().to_vec(), true)
    } else {
        unreachable!("validated exactly one signature flag")
    };

    let finalized = match finalize_publication(&prepared, &sig_bytes, is_b64_flag) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: finalize-publication failed: {err}");
            exit(2);
        }
    };

    let pub_json_bytes = match encode_carried_publication_set_canonical(&finalized.publication_set)
    {
        Ok(b) => b,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
    };

    let file_mode = if mode_0600 { 0o600 } else { 0o644 };
    if let Err(err) = write_atomic_file(out_path, &pub_json_bytes, file_mode) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "record_ref": finalized.record_ref,
        "publisher_key_id": finalized.publisher_key_id,
        "algorithm": finalized.algorithm.as_str(),
        "definition_count": finalized.definition_count,
        "signature_normalized": finalized.signature_was_normalized,
        "out": out_path.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical finalize-publication summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn load_pubkey_entry_from_cli(
    raw_arg: &str,
    alg_opt: Option<&str>,
    flag_label: &str,
) -> Result<PublicKeyEntry, String> {
    let parsed_alg = match alg_opt {
        Some(a) => Some(SignatureAlgorithm::parse(a)?),
        None => None,
    };
    let raw_bytes = load_public_key_file_or_inline(raw_arg, flag_label)?;
    parse_public_key_entry(&raw_bytes, parsed_alg, flag_label)
}

fn load_sig_input_from_cli(
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    cmd_name: &str,
) -> Result<(Vec<u8>, bool), String> {
    if signature_file.is_some() == signature_b64.is_some() {
        return Err(format!(
            "{cmd_name} requires exactly one of --signature-file or --signature-b64"
        ));
    }
    if let Some(sf) = signature_file {
        let b = fs::read(sf)
            .map_err(|e| format!("cannot read --signature-file {}: {e}", sf.display()))?;
        Ok((b, false))
    } else if let Some(sb64) = signature_b64 {
        Ok((sb64.as_bytes().to_vec(), true))
    } else {
        unreachable!()
    }
}

fn parse_optional_rfc3339_utc(
    raw: Option<&str>,
    label: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
    match raw {
        None => Ok(None),
        Some(s) => {
            if s.ends_with("-00:00") {
                return Err(format!(
                    "invalid {label} ({s}): unknown -00:00 offset is outside Provenance v2 Timestamp profile"
                ));
            }
            let dt = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("invalid {label} RFC3339 timestamp ({s}): {e}"))?
                .with_timezone(&chrono::Utc);
            Ok(Some(dt))
        }
    }
}

fn parse_optional_details_json(
    raw: Option<&str>,
) -> Result<Option<serde_json::Map<String, Value>>, String> {
    match raw {
        None => Ok(None),
        Some(s) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(m)) => Ok(Some(m)),
            Ok(_) => Err("--details-json must be a JSON object".to_string()),
            Err(e) => Err(format!("invalid --details-json: {e}")),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_claim_subcommand(
    gateway_url: &str,
    claim_code_file: Option<&Path>,
    claim_code_env: &str,
    root_public_key: &str,
    algorithm: Option<&str>,
    holder: Option<String>,
    custody: Option<String>,
    identity: Option<String>,
    roots_file: Option<&Path>,
    additional_roots: &[String],
    threshold: usize,
    recovery_keys: Vec<String>,
    generate_recovery_keys: &[PathBuf],
    custodians: &[String],
    allow_permanent_roots: bool,
    force: bool,
    trusted_publishers: &[String],
    allow_untrusted_publisher: bool,
    allow_large_ed25519_pae: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    if trusted_publishers.is_empty() && !allow_untrusted_publisher {
        eprintln!(
            "r5e-endpoint-helper: refusing claim without publisher trust pin: pass --trusted-publisher <keyid> or --allow-untrusted-publisher"
        );
        exit(2);
    }

    let mut parsed_custodians = Vec::with_capacity(custodians.len());
    for c_spec in custodians {
        match parse_custodian_spec(c_spec) {
            Ok(c) => parsed_custodians.push(c),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    if recovery_keys.is_empty() && generate_recovery_keys.is_empty() && parsed_custodians.is_empty()
    {
        eprintln!("{IRREVERSIBLE_CLAIM_WARNING}");
        if !allow_permanent_roots {
            eprintln!(
                "r5e-endpoint-helper: refusing permanent unrotatable root configuration: pass --generate-recovery-key <path>, --recovery-key <keyid>, or --custodian <uri>[=<keyid>], or pass --allow-permanent-roots to confirm"
            );
            exit(2);
        }
    }

    let code = match resolve_claim_code(claim_code_file, claim_code_env) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let claiming_pubkey =
        match load_pubkey_entry_from_cli(root_public_key, algorithm, "--root-public-key") {
            Ok(pk) => pk,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let mut all_recovery_keys = recovery_keys;
    let mut generated_recovery_meta = Vec::with_capacity(generate_recovery_keys.len());
    for rec_path in generate_recovery_keys {
        match generate_and_save_recovery_key(rec_path, force) {
            Ok((kid, saved_path)) => {
                all_recovery_keys.push(kid.clone());
                generated_recovery_meta.push(json!({
                    "keyId": kid,
                    "path": saved_path,
                }));
            }
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    let roots = match assemble_claim_roots_for_pubkey(
        &claiming_pubkey.algorithm,
        &claiming_pubkey.bytes,
        holder,
        custody,
        identity,
        roots_file,
        additional_roots,
    ) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let prepare_req = PrepareClaimRequest {
        code,
        claimed_by: claiming_pubkey.keyid.clone(),
        roots,
        threshold,
        recovery_keys: if all_recovery_keys.is_empty() {
            None
        } else {
            Some(all_recovery_keys.clone())
        },
        custodians: if parsed_custodians.is_empty() {
            None
        } else {
            Some(parsed_custodians)
        },
    };

    let cfg = ClaimClientConfig::new(gateway_url);
    let (ceremony, pae_bytes) = match prepare_detached_claim_ceremony(
        &cfg,
        &claiming_pubkey,
        &prepare_req,
        trusted_publishers,
        allow_untrusted_publisher,
        allow_large_ed25519_pae,
    ) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: prepare-claim failed: {err}");
            exit(2);
        }
    };

    let ceremony_val = serde_json::to_value(&ceremony).expect("serialize PreparedClaimCeremony");
    let ceremony_bytes =
        encode_canonical_json(&ceremony_val).expect("canonical PreparedClaimCeremony JSON");
    if let Err(err) = write_atomic_file(out_prepared, &ceremony_bytes, 0o600) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o600) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let mut summary = json!({
        "ok": true,
        "deployment": ceremony.inspection.deployment,
        "draftDeploymentRef": ceremony.inspection.draft_deployment_ref,
        "chainStartedRef": ceremony.inspection.chain_started_ref,
        "claimedByKeyId": ceremony.inspection.claimed_by_key_id,
        "algorithm": ceremony.claiming_root_pubkey.algorithm,
        "publisherKeyId": ceremony.inspection.publisher_key_id,
        "publisherTrusted": ceremony.inspection.publisher_trusted,
        "publicationRef": ceremony.inspection.publication_ref,
        "definitionCount": ceremony.inspection.definition_count,
        "paeBytes": pae_bytes.len(),
        "paeSha256": ceremony.pae_sha256,
        "outPrepared": out_prepared.to_string_lossy(),
        "outPae": out_pae.to_string_lossy(),
    });
    if !generated_recovery_meta.is_empty() {
        summary["generatedRecoveryKeys"] = json!(generated_recovery_meta);
    }
    let summary_bytes = encode_canonical_json(&summary).expect("canonical prepare-claim summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_claim_subcommand(
    prepared_path: &Path,
    gateway_url_override: Option<&str>,
    claim_code_file: Option<&Path>,
    claim_code_env: &str,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    out_receipt: Option<&Path>,
) {
    let (sig_bytes, is_b64_flag) =
        match load_sig_input_from_cli(signature_file, signature_b64, "finalize-claim") {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let code = match resolve_claim_code(claim_code_file, claim_code_env) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let ceremony: PreparedClaimCeremony = match serde_json::from_str(&raw_prep) {
        Ok(c) => c,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let eff_gw = gateway_url_override.unwrap_or(&ceremony.gateway_url);
    let cfg = ClaimClientConfig::new(eff_gw);
    let (finalized, sig_normalized) =
        match finalize_detached_claim_ceremony(&cfg, &ceremony, &code, &sig_bytes, is_b64_flag) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: finalize-claim failed: {err}");
                exit(1);
            }
        };

    if let Some(receipt_path) = out_receipt {
        let receipt_obj = json!({
            "chain": &finalized.chain,
            "deployment": &ceremony.inspection.deployment,
            "deploymentRecord": &finalized.deployment_record,
            "chainStarted": &finalized.chain_started,
            "gatewayKey": &finalized.gateway_key,
            "streamPrefix": &finalized.stream_prefix,
            "rootKeyId": &ceremony.claiming_root_pubkey.keyid,
            "rootAlgorithm": &ceremony.claiming_root_pubkey.algorithm,
            "signatureNormalized": sig_normalized,
            "publisher": &ceremony.inspection.publisher_key_id,
            "publisherTrusted": ceremony.inspection.publisher_trusted,
            "publicationRef": &ceremony.inspection.publication_ref,
            "definitionCount": ceremony.inspection.definition_count,
        });
        let receipt_bytes =
            encode_canonical_json(&receipt_obj).expect("canonical finalize-claim receipt");
        if let Err(err) = write_atomic_file(receipt_path, &receipt_bytes, 0o644) {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(1);
        }
    }

    let summary = json!({
        "ok": true,
        "deployment": ceremony.inspection.deployment,
        "chain": finalized.chain,
        "chainStartedRef": finalized.chain_started.record_ref,
        "rootKeyId": ceremony.claiming_root_pubkey.keyid,
        "rootAlgorithm": ceremony.claiming_root_pubkey.algorithm,
        "signatureNormalized": sig_normalized,
        "gatewayKey": finalized.gateway_key,
        "gatewayKeyId": finalized.gateway_key.keyid,
        "streamPrefix": finalized.stream_prefix,
        "publisher": ceremony.inspection.publisher_key_id,
        "publisherTrusted": ceremony.inspection.publisher_trusted,
        "publicationRef": ceremony.inspection.publication_ref,
    });
    let summary_bytes = encode_canonical_json(&summary).expect("canonical finalize-claim summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_endorsement_subcommand(
    issuer_public_key: &str,
    algorithm: Option<&str>,
    subject: Option<String>,
    subject_public_key: Option<&str>,
    gateway_url: Option<&str>,
    deployment: Option<String>,
    stream_prefix: Option<String>,
    grant_token: Option<String>,
    seq: u64,
    previous: Option<String>,
    actor: String,
    kinds: Option<Vec<String>>,
    stream_prefixes: Option<Vec<String>>,
    actor_prefixes: Option<Vec<String>>,
    omit_actor_prefixes: bool,
    acts_for: Option<String>,
    parent: Option<String>,
    role: Option<String>,
    may_endorse: bool,
    captured_at_str: Option<&str>,
    not_before: Option<String>,
    ttl_seconds: u64,
    sealer_keys: Vec<String>,
    details_json: Option<&str>,
    allow_large_ed25519_pae: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    let issuer_pubkey =
        match load_pubkey_entry_from_cli(issuer_public_key, algorithm, "--issuer-public-key") {
            Ok(pk) => pk,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let derived_subj_id = match subject_public_key {
        Some(spk) => match load_pubkey_entry_from_cli(spk, None, "--subject-public-key") {
            Ok(pk) => Some(pk.keyid),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        },
        None => None,
    };
    if let (Some(ref s1), Some(ref s2)) = (&subject, &derived_subj_id) {
        if s1 != s2 {
            eprintln!(
                "r5e-endpoint-helper: --subject ({s1}) does not match --subject-public-key ({s2})"
            );
            exit(2);
        }
    }

    let fetched_status = match gateway_url {
        Some(gw_url) => {
            let cfg = ClaimClientConfig::new(gw_url);
            match get_deployment_status_raw(&cfg) {
                Ok(pair) => Some(pair),
                Err(err) => {
                    if (subject.is_none() && derived_subj_id.is_none())
                        || (deployment.is_none() && stream_prefix.is_none())
                    {
                        eprintln!("r5e-endpoint-helper: GET {gw_url}/v1/deployment failed: {err}");
                        exit(1);
                    }
                    None
                }
            }
        }
        None => None,
    };

    let resolved_subject = match subject.or(derived_subj_id).or_else(|| {
        fetched_status
            .as_ref()
            .and_then(|(s, _)| s.gateway_key.as_ref().map(|k| k.keyid.clone()))
    }) {
        Some(s) => s,
        None => {
            eprintln!(
                "r5e-endpoint-helper: --subject (or --subject-public-key or --gateway-url) is required"
            );
            exit(2);
        }
    };

    let resolved_prefix = if let Some(sp) = stream_prefix {
        sp
    } else if let Some(dep) = deployment {
        format!("urn:r5e:stream:{dep}:")
    } else if let Some(sp) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.stream_prefix.clone())
    {
        sp
    } else if let Some(dep) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.deployment.clone())
    {
        format!("urn:r5e:stream:{dep}:")
    } else {
        eprintln!(
            "r5e-endpoint-helper: pass --deployment <slug>, --stream-prefix <prefix>, or --gateway-url <url>"
        );
        exit(2);
    };

    let explicit_captured_at = match parse_optional_rfc3339_utc(captured_at_str, "--captured-at") {
        Ok(dt) => dt,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    let effective_captured_at = explicit_captured_at.or_else(|| {
        fetched_status
            .as_ref()
            .and_then(|(s, raw)| {
                latest_status_captured_at_utc(raw).or_else(|| {
                    s.deployment_record
                        .as_ref()
                        .and_then(record_captured_at_utc)
                })
            })
            .map(|floor| std::cmp::max(chrono::Utc::now(), ceil_to_micros(floor)))
    });

    let details_map = match parse_optional_details_json(details_json) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let effective_sealer_keys = if !sealer_keys.is_empty() {
        sealer_keys
    } else if let Some(gw_kid) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.gateway_key.as_ref().map(|k| k.keyid.clone()))
    {
        vec![gw_kid]
    } else if grant_token.is_none() && may_endorse {
        vec![resolved_subject.clone()]
    } else {
        Vec::new()
    };

    let effective_actor_prefixes = if omit_actor_prefixes {
        None
    } else if let Some(aps) = actor_prefixes {
        Some(aps)
    } else {
        Some(vec!["urn:r5e:".to_string()])
    };

    let params = DetachedEndorsementParams {
        issuer_pubkey,
        subject_key_id: resolved_subject,
        stream_prefix: resolved_prefix,
        grant_substream_token: grant_token,
        seq,
        previous,
        actor,
        kinds: kinds.unwrap_or_else(default_gateway_grant_kinds),
        stream_prefixes,
        actor_prefixes: effective_actor_prefixes,
        acts_for,
        parent,
        role,
        may_endorse,
        captured_at: effective_captured_at,
        not_before_override: not_before,
        ttl_seconds,
        sealer_keys: effective_sealer_keys,
        details: details_map,
        allow_large_ed25519_pae,
    };

    let (prepared, pae_bytes) = match prepare_detached_endorsement(&params) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: prepare-endorsement failed: {err}");
            exit(2);
        }
    };

    let prep_val = serde_json::to_value(&prepared).expect("serialize PreparedEndorsement");
    let prep_bytes = encode_canonical_json(&prep_val).expect("canonical PreparedEndorsement JSON");
    if let Err(err) = write_atomic_file(out_prepared, &prep_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "recordRef": prepared.record_ref,
        "issuerKeyId": prepared.issuer_pubkey.keyid,
        "algorithm": prepared.issuer_pubkey.algorithm,
        "subjectKeyId": prepared.subject_key_id,
        "stream": prepared.stream,
        "profileRef": prepared.profile_ref,
        "paeBytes": pae_bytes.len(),
        "paeSha256": prepared.pae_sha256,
        "outPrepared": out_prepared.to_string_lossy(),
        "outPae": out_pae.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical prepare-endorsement summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_endorsement_subcommand(
    prepared_path: &Path,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    with_grant_files: &[PathBuf],
    out_path: &Path,
    submit: bool,
    gateway_url: Option<&str>,
) {
    if submit && gateway_url.is_none() {
        eprintln!(
            "r5e-endpoint-helper: finalize-endorsement --submit requires --gateway-url <url>"
        );
        exit(2);
    }
    let (sig_bytes, is_b64_flag) =
        match load_sig_input_from_cli(signature_file, signature_b64, "finalize-endorsement") {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedEndorsement = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let finalized = match finalize_detached_endorsement(&prepared, &sig_bytes, is_b64_flag) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: finalize-endorsement failed: {err}");
            exit(2);
        }
    };

    let mut sets = vec![finalized.grant_request.clone()];
    for gf in with_grant_files {
        let raw_gf = match fs::read_to_string(gf) {
            Ok(s) => s,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cannot read --with-grant-file {}: {err}",
                    gf.display()
                );
                exit(2);
            }
        };
        let parsed_gf: SubmitGrantsRequest = match serde_json::from_str(&raw_gf) {
            Ok(g) => g,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: invalid SubmitGrantsRequest JSON in {}: {err}",
                    gf.display()
                );
                exit(2);
            }
        };
        sets.push(parsed_gf);
    }

    let merged_req = match merge_submit_grants_requests(&sets) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let grant_val = serde_json::to_value(&merged_req).expect("serialize SubmitGrantsRequest");
    let grant_bytes =
        encode_canonical_json(&grant_val).expect("canonical SubmitGrantsRequest JSON");
    if let Err(err) = write_atomic_file(out_path, &grant_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let mut summary = json!({
        "ok": true,
        "endorsementRef": finalized.endorsement.record_ref,
        "issuerKeyId": finalized.issuer_key_id,
        "subjectKeyId": finalized.subject_key_id,
        "stream": finalized.stream,
        "profileRef": finalized.profile_ref,
        "signatureNormalized": finalized.signature_was_normalized,
        "recordCount": merged_req.records.len(),
        "out": out_path.to_string_lossy(),
        "submitted": submit,
    });

    if submit {
        let gw = gateway_url.expect("checked Some when submit");
        let cfg = ClaimClientConfig::new(gw);
        match submit_deployment_grants(&cfg, &merged_req) {
            Ok(resp) => {
                summary["status"] = json!(resp.status);
                summary["recordedRefs"] = json!(resp.recorded_refs);
            }
            Err(err) => {
                eprintln!("r5e-endpoint-helper: POST /v1/deployment/grants failed: {err}");
                exit(1);
            }
        }
    }

    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical finalize-endorsement summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_principal_subcommand(
    public_key: &str,
    algorithm: Option<&str>,
    holder: String,
    custody: Option<String>,
    identity: Option<String>,
    gateway_url: Option<&str>,
    deployment: Option<String>,
    stream_prefix: Option<String>,
    actor: String,
    captured_at_str: Option<&str>,
    sealer_keys: Vec<String>,
    details_json: Option<&str>,
    allow_large_ed25519_pae: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    let principal_pubkey = match load_pubkey_entry_from_cli(public_key, algorithm, "--public-key") {
        Ok(pk) => pk,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let fetched_status = match gateway_url {
        Some(gw_url) => {
            let cfg = ClaimClientConfig::new(gw_url);
            match get_deployment_status_raw(&cfg) {
                Ok(pair) => Some(pair),
                Err(err) => {
                    if deployment.is_none() && stream_prefix.is_none() {
                        eprintln!("r5e-endpoint-helper: GET {gw_url}/v1/deployment failed: {err}");
                        exit(1);
                    }
                    None
                }
            }
        }
        None => None,
    };

    let resolved_prefix = if let Some(sp) = stream_prefix {
        sp
    } else if let Some(dep) = deployment {
        format!("urn:r5e:stream:{dep}:")
    } else if let Some(sp) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.stream_prefix.clone())
    {
        sp
    } else if let Some(dep) = fetched_status
        .as_ref()
        .and_then(|(s, _)| s.deployment.clone())
    {
        format!("urn:r5e:stream:{dep}:")
    } else {
        eprintln!(
            "r5e-endpoint-helper: pass --deployment <slug>, --stream-prefix <prefix>, or --gateway-url <url>"
        );
        exit(2);
    };

    let explicit_captured_at = match parse_optional_rfc3339_utc(captured_at_str, "--captured-at") {
        Ok(dt) => dt,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    let effective_captured_at = explicit_captured_at.or_else(|| {
        fetched_status
            .as_ref()
            .and_then(|(s, raw)| {
                latest_status_captured_at_utc(raw).or_else(|| {
                    s.deployment_record
                        .as_ref()
                        .and_then(record_captured_at_utc)
                })
            })
            .map(|floor| std::cmp::max(chrono::Utc::now(), ceil_to_micros(floor)))
    });

    let details_map = match parse_optional_details_json(details_json) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let params = DetachedPrincipalParams {
        principal_pubkey,
        stream_prefix: resolved_prefix,
        holder,
        custody,
        identity,
        actor,
        captured_at: effective_captured_at,
        sealer_keys,
        details: details_map,
        allow_large_ed25519_pae,
    };

    let (prepared, pae_bytes) = match prepare_detached_principal(&params) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: prepare-principal failed: {err}");
            exit(2);
        }
    };

    let prep_val = serde_json::to_value(&prepared).expect("serialize PreparedPrincipal");
    let prep_bytes = encode_canonical_json(&prep_val).expect("canonical PreparedPrincipal JSON");
    if let Err(err) = write_atomic_file(out_prepared, &prep_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "recordRef": prepared.record_ref,
        "keyId": prepared.principal_pubkey.keyid,
        "algorithm": prepared.principal_pubkey.algorithm,
        "stream": prepared.stream,
        "profileRef": prepared.profile_ref,
        "paeBytes": pae_bytes.len(),
        "paeSha256": prepared.pae_sha256,
        "outPrepared": out_prepared.to_string_lossy(),
        "outPae": out_pae.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical prepare-principal summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_principal_subcommand(
    prepared_path: &Path,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    out_path: &Path,
) {
    let (sig_bytes, is_b64_flag) =
        match load_sig_input_from_cli(signature_file, signature_b64, "finalize-principal") {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedPrincipal = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let finalized = match finalize_detached_principal(&prepared, &sig_bytes, is_b64_flag) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: finalize-principal failed: {err}");
            exit(2);
        }
    };

    let out_val =
        serde_json::to_value(&finalized.grant_request).expect("serialize SubmitGrantsRequest");
    let out_bytes = encode_canonical_json(&out_val).expect("canonical SubmitGrantsRequest JSON");
    if let Err(err) = write_atomic_file(out_path, &out_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "principalRef": finalized.principal.record_ref,
        "keyId": finalized.key_id,
        "stream": finalized.stream,
        "profileRef": finalized.profile_ref,
        "signatureNormalized": finalized.signature_was_normalized,
        "out": out_path.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical finalize-principal summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_root_change_subcommand(
    deployment: String,
    chain: String,
    replaces: String,
    seq: u64,
    authorization: CliAuthorizationMode,
    signer_public_key: &str,
    algorithm: Option<&str>,
    root_keys: &[String],
    roots_file: Option<&Path>,
    additional_roots: &[String],
    threshold: usize,
    recovery_keys: Vec<String>,
    generate_recovery_keys: &[PathBuf],
    force: bool,
    custodians: &[String],
    reason: Option<String>,
    actor: String,
    captured_at_str: Option<&str>,
    roots_changed_schema_ref: Option<String>,
    approval_schema_ref: Option<String>,
    roots_changed_definition_file: Option<&Path>,
    allow_large_ed25519_pae: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    let signer_pubkey =
        match load_pubkey_entry_from_cli(signer_public_key, algorithm, "--signer-public-key") {
            Ok(pk) => pk,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let mut roots = Vec::new();
    if let Some(rf) = roots_file {
        let raw = match fs::read_to_string(rf) {
            Ok(s) => s,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: cannot read --roots-file {}: {err}",
                    rf.display()
                );
                exit(2);
            }
        };
        let parsed_arr: Vec<Value> = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                eprintln!(
                    "r5e-endpoint-helper: invalid JSON array in --roots-file {}: {err}",
                    rf.display()
                );
                exit(2);
            }
        };
        for (i, item) in parsed_arr.iter().enumerate() {
            let s = serde_json::to_string(item).unwrap();
            match parse_flexible_root_json(&s, &format!("--roots-file[{i}]")) {
                Ok(r) => roots.push(r),
                Err(err) => {
                    eprintln!("r5e-endpoint-helper: {err}");
                    exit(2);
                }
            }
        }
    }
    for spec in root_keys {
        match parse_root_key_spec(spec, "--root-key") {
            Ok(r) => roots.push(r),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }
    for spec in additional_roots {
        match parse_root_key_spec(spec, "--additional-root") {
            Ok(r) => roots.push(r),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    let mut parsed_custodians = Vec::with_capacity(custodians.len());
    for c_spec in custodians {
        match parse_custodian_spec(c_spec) {
            Ok(c) => parsed_custodians.push(c),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    let custom_def_blobs = match load_custom_definition_blob(
        roots_changed_definition_file,
        roots_changed_schema_ref.as_deref(),
        "--roots-changed-definition-file",
    ) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let mut all_recovery_keys = recovery_keys;
    for rec_path in generate_recovery_keys {
        match generate_and_save_recovery_key(rec_path, force) {
            Ok((kid, _)) => all_recovery_keys.push(kid),
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        }
    }

    let captured_at = match parse_optional_rfc3339_utc(captured_at_str, "--captured-at") {
        Ok(dt) => dt,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let auth_mode: RootChangeAuthorization = authorization.into();
    let mut params = ProposeRootChangeParams::new(
        deployment, chain, replaces, seq, auth_mode, roots, threshold,
    );
    params.recovery_keys = all_recovery_keys;
    params.custodians = parsed_custodians;
    params.reason = reason;
    params.actor = actor;
    params.captured_at = captured_at;
    params.roots_changed_schema_ref = roots_changed_schema_ref;
    params.approval_schema_ref = approval_schema_ref;
    params.custom_definition_blobs = custom_def_blobs;

    let (prepared, pae_bytes) =
        match prepare_detached_root_change(&signer_pubkey, &params, allow_large_ed25519_pae) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: prepare-root-change failed: {err}");
                exit(2);
            }
        };

    let prep_val = serde_json::to_value(&prepared).expect("serialize PreparedRootChange");
    let prep_bytes = encode_canonical_json(&prep_val).expect("canonical PreparedRootChange JSON");
    if let Err(err) = write_atomic_file(out_prepared, &prep_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "deployment": prepared.deployment,
        "chain": prepared.chain,
        "seq": prepared.seq,
        "changeRef": prepared.record_ref,
        "signer": prepared.signer_pubkey.keyid,
        "algorithm": prepared.signer_pubkey.algorithm,
        "paeBytes": pae_bytes.len(),
        "paeSha256": prepared.pae_sha256,
        "outPrepared": out_prepared.to_string_lossy(),
        "outPae": out_pae.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical prepare-root-change summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_root_change_subcommand(
    prepared_path: &Path,
    signature_file: Option<&Path>,
    signature_b64: Option<&str>,
    out_path: &Path,
) {
    let (sig_bytes, is_b64_flag) =
        match load_sig_input_from_cli(signature_file, signature_b64, "finalize-root-change") {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedRootChange = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let (proposal, sig_norm) =
        match finalize_detached_root_change(&prepared, &sig_bytes, is_b64_flag) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: finalize-root-change failed: {err}");
                exit(2);
            }
        };

    let prop_val = serde_json::to_value(&proposal).expect("serialize RootChangeProposalFile");
    let prop_bytes =
        encode_canonical_json(&prop_val).expect("canonical RootChangeProposalFile JSON");
    if let Err(err) = write_atomic_file(out_path, &prop_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "deployment": proposal.deployment,
        "chain": proposal.chain,
        "seq": proposal.seq,
        "changeRef": proposal.change.record_ref,
        "signer": prepared.signer_pubkey.keyid,
        "signatureNormalized": sig_norm,
        "proposalPath": out_path.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical finalize-root-change summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

#[allow(clippy::too_many_arguments)]
fn run_prepare_root_approval_subcommand(
    proposal_path: &Path,
    root_public_key: &str,
    root_algorithm: Option<&str>,
    custodian: String,
    custodian_public_key: &str,
    custodian_algorithm: Option<&str>,
    reason: Option<String>,
    actor: String,
    captured_at_str: Option<&str>,
    approval_schema_ref: Option<String>,
    approval_definition_file: Option<&Path>,
    allow_large_ed25519_pae: bool,
    out_prepared: &Path,
    out_pae: &Path,
) {
    let raw_prop = match fs::read_to_string(proposal_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --proposal {}: {err}",
                proposal_path.display()
            );
            exit(2);
        }
    };
    let proposal: RootChangeProposalFile = match serde_json::from_str(&raw_prop) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --proposal {}: {err}",
                proposal_path.display()
            );
            exit(2);
        }
    };

    let root_pubkey =
        match load_pubkey_entry_from_cli(root_public_key, root_algorithm, "--root-public-key") {
            Ok(pk) => pk,
            Err(err) => {
                eprintln!("r5e-endpoint-helper: {err}");
                exit(2);
            }
        };
    let cust_pubkey = match load_pubkey_entry_from_cli(
        custodian_public_key,
        custodian_algorithm,
        "--custodian-public-key",
    ) {
        Ok(pk) => pk,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let custom_def_blobs = match load_custom_definition_blob(
        approval_definition_file,
        approval_schema_ref.as_deref(),
        "--approval-definition-file",
    ) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let captured_at = match parse_optional_rfc3339_utc(captured_at_str, "--captured-at") {
        Ok(dt) => dt,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let mut params = ApproveRootChangeParams::new(custodian);
    params.reason = reason;
    params.actor = actor;
    params.captured_at = captured_at;
    params.approval_schema_ref = approval_schema_ref;
    params.custom_definition_blobs = custom_def_blobs;

    let (prepared, pae_bytes) = match prepare_detached_root_approval(
        &proposal,
        &root_pubkey,
        &cust_pubkey,
        &params,
        allow_large_ed25519_pae,
    ) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: prepare-root-approval failed: {err}");
            exit(2);
        }
    };

    let prep_val = serde_json::to_value(&prepared).expect("serialize PreparedRootApproval");
    let prep_bytes = encode_canonical_json(&prep_val).expect("canonical PreparedRootApproval JSON");
    if let Err(err) = write_atomic_file(out_prepared, &prep_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }
    if let Err(err) = write_atomic_file(out_pae, &pae_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "changeRef": prepared.change_ref,
        "approvalRef": prepared.record_ref,
        "root": prepared.root_pubkey.keyid,
        "custodian": prepared.custodian,
        "custodianKey": prepared.custodian_pubkey.keyid,
        "paeBytes": pae_bytes.len(),
        "paeSha256": prepared.pae_sha256,
        "outPrepared": out_prepared.to_string_lossy(),
        "outPae": out_pae.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical prepare-root-approval summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}

fn run_finalize_root_approval_subcommand(
    proposal_path: &Path,
    prepared_path: &Path,
    root_sig_file: Option<&Path>,
    root_sig_b64: Option<&str>,
    cust_sig_file: Option<&Path>,
    cust_sig_b64: Option<&str>,
    out_opt: Option<&Path>,
) {
    let (root_sig, root_is_b64) = match load_sig_input_from_cli(
        root_sig_file,
        root_sig_b64,
        "finalize-root-approval (--root-signature-*)",
    ) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };
    let (cust_sig, cust_is_b64) = match load_sig_input_from_cli(
        cust_sig_file,
        cust_sig_b64,
        "finalize-root-approval (--custodian-signature-*)",
    ) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: {err}");
            exit(2);
        }
    };

    let raw_prop = match fs::read_to_string(proposal_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --proposal {}: {err}",
                proposal_path.display()
            );
            exit(2);
        }
    };
    let mut prop_obj: RootChangeProposalFile = match serde_json::from_str(&raw_prop) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --proposal {}: {err}",
                proposal_path.display()
            );
            exit(2);
        }
    };

    let raw_prep = match fs::read_to_string(prepared_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: cannot read --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };
    let prepared: PreparedRootApproval = match serde_json::from_str(&raw_prep) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "r5e-endpoint-helper: invalid JSON in --prepared {}: {err}",
                prepared_path.display()
            );
            exit(2);
        }
    };

    let (approval_rec, root_norm, cust_norm) = match finalize_detached_root_approval(
        &mut prop_obj,
        &prepared,
        &root_sig,
        root_is_b64,
        &cust_sig,
        cust_is_b64,
    ) {
        Ok(tup) => tup,
        Err(err) => {
            eprintln!("r5e-endpoint-helper: finalize-root-approval failed: {err}");
            exit(2);
        }
    };

    let dest_path = out_opt.unwrap_or(proposal_path);
    let updated_val = serde_json::to_value(&prop_obj).expect("serialize updated proposal");
    let updated_bytes = encode_canonical_json(&updated_val).expect("canonical updated proposal");
    if let Err(err) = write_atomic_file(dest_path, &updated_bytes, 0o644) {
        eprintln!("r5e-endpoint-helper: {err}");
        exit(1);
    }

    let summary = json!({
        "ok": true,
        "changeRef": prop_obj.change.record_ref,
        "approvalRef": approval_rec.record_ref,
        "root": prepared.root_pubkey.keyid,
        "custodian": prepared.custodian,
        "custodianKey": prepared.custodian_pubkey.keyid,
        "rootSignatureNormalized": root_norm,
        "custodianSignatureNormalized": cust_norm,
        "approvalCount": prop_obj.approvals.len(),
        "proposalPath": dest_path.to_string_lossy(),
    });
    let summary_bytes =
        encode_canonical_json(&summary).expect("canonical finalize-root-approval summary");
    println!("{}", String::from_utf8_lossy(&summary_bytes));
}
