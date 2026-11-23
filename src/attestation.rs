//! Provenance v2 key derivation and DSSE signing on the endpoint (`VERIFY-V2.md` §§2.3–2.4).
//!
//! Short-lived device keys sign endpoint observations and prevention records locally with
//! zero remote KMS round-trip on the hot path.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const PROVENANCE_V2_PAYLOAD_TYPE: &str = "application/vnd.r5e.provenance-evidence+json;v=2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEndpointRecord {
    /// `evidence:sha256:<64 lowercase hex>` of canonical payload bytes alone.
    #[serde(rename = "ref")]
    pub record_ref: String,
    pub envelope: DsseEnvelope,
}

/// Computes `key:ed25519:sha256:<hex>` = SHA-256(uvarint(7) || "ed25519" || pubkey_32)
/// per `VERIFY-V2.md` §2.3.
pub fn ed25519_key_id(public_key_bytes: &[u8; 32]) -> String {
    let alg = b"ed25519";
    let mut hasher = Sha256::new();
    hasher.update([alg.len() as u8]);
    hasher.update(alg);
    hasher.update(public_key_bytes);
    let digest = hasher.finalize();
    format!(
        "key:ed25519:sha256:{}",
        crate::policy_gate::hex_lower(&digest)
    )
}

/// Builds DSSEv1 pre-authentication encoding (`VERIFY-V2.md` §2.4):
/// `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`.
pub fn dsse_pae(payload_type: &str, payload_bytes: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload_bytes.len()
    );
    let mut out = Vec::with_capacity(header.len() + payload_bytes.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload_bytes);
    out
}

/// Encodes a restricted JSON value into canonical JSON (`VERIFY-V2.md` §2.1: keys sorted
/// lexicographically, integers within ±(2^53 - 1), no floats, RFC 8785 short escapes).
pub fn encode_canonical_json(val: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    write_canonical(val, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(val: &Value, out: &mut String) -> Result<(), String> {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            const MAX_SAFE: i64 = (1_i64 << 53) - 1;
            let i = n.as_i64().ok_or_else(|| {
                format!("non-integer or out-of-range number in canonical JSON: {n}")
            })?;
            if !(-MAX_SAFE..=MAX_SAFE).contains(&i) {
                return Err(format!("integer outside ±(2^53 - 1): {i}"));
            }
            out.push_str(&i.to_string());
        }
        Value::String(s) => write_canonical_str(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => write_canonical_obj(map, out)?,
    }
    Ok(())
}

fn write_canonical_obj(map: &Map<String, Value>, out: &mut String) -> Result<(), String> {
    let mut keys: Vec<&String> = map.keys().collect();
    for k in &keys {
        if k.chars().any(|ch| (ch as u32) > 0xFFFF) {
            return Err(format!("object key contains character above U+FFFF: {k}"));
        }
    }
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    out.push('{');
    for (idx, k) in keys.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        write_canonical_str(k, out);
        out.push(':');
        write_canonical(&map[*k], out)?;
    }
    out.push('}');
    Ok(())
}

fn write_canonical_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Signs a Provenance v2 payload object as Signer 1 (`issuer`) and computes its
/// payload-only `evidence:sha256:...` reference.
pub fn sign_v2_record(
    signing_key: &SigningKey,
    payload_obj: Map<String, Value>,
) -> Result<SignedEndpointRecord, String> {
    sign_v2_record_multi(&[signing_key], payload_obj)
}

/// Signs a Provenance v2 payload object with one or more signers (e.g. 2 signers for
/// `Badge` or `Succession` per `A4` / `VERIFY-V2.md` §5), setting `issuer` to Signer 1's `KeyId`.
pub fn sign_v2_record_multi(
    signers: &[&SigningKey],
    mut payload_obj: Map<String, Value>,
) -> Result<SignedEndpointRecord, String> {
    let first = signers
        .first()
        .ok_or_else(|| "sign_v2_record_multi requires at least one signer".to_string())?;
    let issuer_keyid = ed25519_key_id(&first.verifying_key().to_bytes());
    payload_obj.insert("issuer".to_string(), Value::String(issuer_keyid));

    let canonical_payload = encode_canonical_json(&Value::Object(payload_obj))?;
    let ref_digest = Sha256::digest(&canonical_payload);
    let record_ref = format!(
        "evidence:sha256:{}",
        crate::policy_gate::hex_lower(&ref_digest)
    );

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &canonical_payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for key in signers {
        let keyid = ed25519_key_id(&key.verifying_key().to_bytes());
        let sig = key.sign(&pae);
        signatures.push(DsseSignature {
            keyid,
            sig: BASE64_STANDARD.encode(sig.to_bytes()),
        });
    }

    Ok(SignedEndpointRecord {
        record_ref,
        envelope: DsseEnvelope {
            payload_type: PROVENANCE_V2_PAYLOAD_TYPE.to_string(),
            payload: BASE64_STANDARD.encode(&canonical_payload),
            signatures,
        },
    })
}

/// Computes `bytes:sha256:<64 lowercase hex>` for arbitrary content bytes.
pub fn bytes_ref(raw: &[u8]) -> String {
    let digest = Sha256::digest(raw);
    format!("bytes:sha256:{}", crate::policy_gate::hex_lower(&digest))
}

/// Computes `evidence:sha256:<64 lowercase hex>` over canonical Provenance v2 payload bytes.
pub fn evidence_ref(canonical_payload: &[u8]) -> String {
    let digest = Sha256::digest(canonical_payload);
    format!("evidence:sha256:{}", crate::policy_gate::hex_lower(&digest))
}

/// Reads `N` cryptographically random bytes from the OS CSPRNG (`/dev/urandom` on Unix).
pub fn generate_os_random_bytes<const N: usize>() -> Result<[u8; N], String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
        let mut buf = [0u8; N];
        f.read_exact(&mut buf)
            .map_err(|e| format!("failed to read {N} bytes from /dev/urandom: {e}"))?;
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        Err("OS random byte generation via /dev/urandom requires a Unix platform".to_string())
    }
}

/// Reads 32 cryptographically random seed bytes from the OS CSPRNG (`/dev/urandom` on Unix).
pub fn generate_os_random_seed_32() -> Result<[u8; 32], String> {
    generate_os_random_bytes::<32>()
}

const PKCS8_ED25519_INNER_PREFIX: [u8; 11] = [
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PKCS8_V1_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Encodes a 32-byte Ed25519 private seed as an RFC 8410 §7 PKCS#8 v1 PEM (`-----BEGIN PRIVATE KEY-----`).
pub fn encode_pkcs8_ed25519_pem(seed: &[u8; 32]) -> String {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&PKCS8_V1_ED25519_PREFIX);
    der.extend_from_slice(seed);
    let b64 = BASE64_STANDARD.encode(&der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// Encodes a 32-byte Ed25519 public key as an RFC 8410 §4 SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
pub fn encode_spki_ed25519_pem(public_key_bytes: &[u8; 32]) -> String {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&SPKI_ED25519_PREFIX);
    der.extend_from_slice(public_key_bytes);
    let b64 = BASE64_STANDARD.encode(&der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

fn extract_pem_body(text: &str, begin_marker: &str, end_marker: &str) -> Option<String> {
    let start = text.find(begin_marker)? + begin_marker.len();
    let rest = &text[start..];
    let end = rest.find(end_marker)?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    Some(body)
}

/// Parses an Ed25519 `SigningKey` from raw 32-byte seed, RFC 8410 PKCS#8 v1/v2 PEM
/// (`-----BEGIN PRIVATE KEY-----` or `-----BEGIN ED25519 PRIVATE KEY-----`), 64-char hex seed,
/// or canonical 32-byte base64 seed. Never embeds secret bytes in error messages.
pub fn parse_ed25519_signing_key_bytes(
    raw_bytes: &[u8],
    source_label: &str,
) -> Result<SigningKey, String> {
    if raw_bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(raw_bytes);
        return Ok(SigningKey::from_bytes(&seed));
    }
    if raw_bytes.len() >= 48 {
        if let Some(pos) = raw_bytes
            .windows(PKCS8_ED25519_INNER_PREFIX.len())
            .position(|w| w == PKCS8_ED25519_INNER_PREFIX)
        {
            let seed_start = pos + PKCS8_ED25519_INNER_PREFIX.len();
            if raw_bytes.len() >= seed_start + 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&raw_bytes[seed_start..seed_start + 32]);
                return Ok(SigningKey::from_bytes(&seed));
            }
        }
    }

    let text = std::str::from_utf8(raw_bytes).map_err(|_| {
        format!(
            "invalid Ed25519 private key in {source_label}: expected PKCS#8 PEM, 32 raw bytes, or canonical base64 of 32 bytes"
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("Ed25519 private key in {source_label} is empty"));
    }

    if trimmed.contains("-----BEGIN PUBLIC KEY-----") {
        return Err(format!(
            "{source_label} contains a PUBLIC key PEM where an Ed25519 PRIVATE key is required"
        ));
    }

    if let Some(b64_body) = extract_pem_body(
        trimmed,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
    )
    .or_else(|| {
        extract_pem_body(
            trimmed,
            "-----BEGIN ED25519 PRIVATE KEY-----",
            "-----END ED25519 PRIVATE KEY-----",
        )
    }) {
        let der = BASE64_STANDARD
            .decode(&b64_body)
            .map_err(|_| format!("invalid PEM base64 body in {source_label}"))?;
        if der.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&der);
            return Ok(SigningKey::from_bytes(&seed));
        }
        if let Some(pos) = der
            .windows(PKCS8_ED25519_INNER_PREFIX.len())
            .position(|w| w == PKCS8_ED25519_INNER_PREFIX)
        {
            let seed_start = pos + PKCS8_ED25519_INNER_PREFIX.len();
            if der.len() >= seed_start + 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&der[seed_start..seed_start + 32]);
                return Ok(SigningKey::from_bytes(&seed));
            }
        }
        return Err(format!(
            "unsupported PKCS#8 algorithm or malformed Ed25519 private key PEM in {source_label}"
        ));
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut seed = [0u8; 32];
        let (chunks, _) = trimmed.as_bytes().as_chunks::<2>();
        for (i, chunk) in chunks.iter().enumerate() {
            let s = std::str::from_utf8(chunk).unwrap_or_default();
            seed[i] = u8::from_str_radix(s, 16)
                .map_err(|_| format!("invalid hex seed in {source_label}"))?;
        }
        return Ok(SigningKey::from_bytes(&seed));
    }

    let decoded = decode_strict_base64(trimmed)
        .map_err(|_| format!("invalid base64 or PEM Ed25519 private key in {source_label}"))?;
    let seed: [u8; 32] = decoded.try_into().map_err(|_| {
        format!("Ed25519 private seed in {source_label} must decode to exactly 32 bytes")
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parses an Ed25519 32-byte public key from SPKI PEM (`-----BEGIN PUBLIC KEY-----`), JSON
/// (`{"algorithm":"ed25519","bytes":"..."}` or `{"publicKey":{"algorithm":"ed25519","bytes":"..."}}`),
/// raw 32 bytes, or canonical base64 of 32 bytes, validating it is a valid Ed25519 curve point.
pub fn parse_ed25519_public_key_bytes(
    raw_bytes: &[u8],
    source_label: &str,
) -> Result<[u8; 32], String> {
    let verify_point = |arr: [u8; 32]| -> Result<[u8; 32], String> {
        let _ = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("{source_label}: invalid Ed25519 public key curve point: {e}"))?;
        Ok(arr)
    };

    if raw_bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw_bytes);
        return verify_point(arr);
    }
    if raw_bytes.len() == 44 && raw_bytes.starts_with(&SPKI_ED25519_PREFIX) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_bytes[12..44]);
        return verify_point(arr);
    }

    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| format!("invalid Ed25519 public key in {source_label}"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("Ed25519 public key in {source_label} is empty"));
    }

    if let Some(b64_body) = extract_pem_body(
        trimmed,
        "-----BEGIN PUBLIC KEY-----",
        "-----END PUBLIC KEY-----",
    ) {
        let der = BASE64_STANDARD
            .decode(&b64_body)
            .map_err(|_| format!("invalid SPKI PEM base64 in {source_label}"))?;
        if der.len() == 44 && der.starts_with(&SPKI_ED25519_PREFIX) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&der[12..44]);
            return verify_point(arr);
        }
        return Err(format!(
            "unsupported SPKI algorithm or malformed Ed25519 public key PEM in {source_label}"
        ));
    }

    if trimmed.starts_with('{') {
        let val: Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("invalid public key JSON in {source_label}: {e}"))?;
        let pk_obj = val
            .get("publicKey")
            .unwrap_or(&val)
            .as_object()
            .ok_or_else(|| format!("{source_label}: expected JSON object for publicKey"))?;
        let alg = pk_obj
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if alg != "ed25519" {
            return Err(format!(
                "{source_label}: unsupported public key algorithm {alg:?}"
            ));
        }
        let b64 = pk_obj
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{source_label}: missing string bytes in publicKey JSON"))?;
        let raw = decode_strict_base64(b64)
            .map_err(|e| format!("{source_label}: invalid public key base64: {e}"))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| format!("{source_label}: Ed25519 public key must be 32 bytes"))?;
        return verify_point(arr);
    }

    let raw = decode_strict_base64(trimmed)
        .map_err(|e| format!("{source_label}: invalid public key base64: {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| format!("{source_label}: Ed25519 public key must be 32 bytes"))?;
    verify_point(arr)
}

/// Writes a 32-byte Ed25519 private seed to `path` with strict `0600` permissions (RFC 8410 PKCS#8
/// PEM when `path` ends with `.pem`, otherwise canonical base64 seed + newline), refusing to
/// overwrite any existing file unless `force == true`.
pub fn write_private_key_file_0600(
    path: &std::path::Path,
    seed: &[u8; 32],
    force: bool,
) -> Result<(), String> {
    if !force && path.exists() {
        return Err(format!(
            "refusing to overwrite existing key file {} (pass --force to overwrite)",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create parent directory for key file: {e}"))?;
        }
    }
    let is_pem = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pem"));
    let content = if is_pem {
        encode_pkcs8_ed25519_pem(seed)
    } else {
        format!("{}\n", BASE64_STANDARD.encode(seed))
    };

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).mode(0o600);
        if force {
            opts.create(true).truncate(true);
        } else {
            opts.create_new(true);
        }
        let mut file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "refusing to overwrite existing key file {} (pass --force to overwrite)",
                    path.display()
                )
            } else {
                format!("cannot create key file {}: {e}", path.display())
            }
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot set 0600 permissions on {}: {e}", path.display()))?;
        file.write_all(content.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("cannot write key file {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content.as_bytes())
            .map_err(|e| format!("cannot write key file {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Writes secret state bytes (`EnrolledStateFile`, etc.) with strict `0600` file permissions on Unix,
/// atomic rename on overwrite (`force == true`), and `sync_all()` durability.
pub fn write_secret_file_0600(
    path: &std::path::Path,
    content: &[u8],
    force: bool,
) -> Result<(), String> {
    crate::outbox_cipher::write_file_0600_durable(path, content, force, "secret state file")
}

/// Append-only Provenance v2 stream & offline bundle assembler (`r5e.provenance-export/v2`)
/// for supervised endpoint sessions.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EndpointBundleRecorder {
    records: Vec<SignedEndpointRecord>,
    blobs: std::collections::BTreeMap<String, (String, Option<String>)>,
    keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    key_algorithms: std::collections::BTreeMap<String, String>,
    stream_heads: std::collections::BTreeMap<String, (u64, String)>,
}

impl EndpointBundleRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all signed records held in the recorder in insertion order.
    pub fn records(&self) -> &[SignedEndpointRecord] {
        &self.records
    }

    /// Returns all content-addressed blobs (`ref -> (base64, media_type)`).
    pub fn blobs(&self) -> &std::collections::BTreeMap<String, (String, Option<String>)> {
        &self.blobs
    }

    /// Looks up a single `BlobEntry` by its `bytes:sha256:...` reference.
    pub fn blob_entry(&self, blob_ref: &str) -> Option<BlobEntry> {
        self.blobs.get(blob_ref).map(|(b64, media_type)| BlobEntry {
            blob_ref: blob_ref.to_string(),
            media_type: media_type.clone(),
            base64: b64.clone(),
        })
    }

    /// Returns all registered public keys (`keyid -> base64`).
    pub fn keys(&self) -> &std::collections::BTreeMap<String, String> {
        &self.keys
    }

    /// Looks up a registered `PublicKeyEntry` by `keyid`.
    pub fn public_key_entry(&self, keyid: &str) -> Option<PublicKeyEntry> {
        self.keys.get(keyid).map(|bytes| PublicKeyEntry {
            keyid: keyid.to_string(),
            algorithm: self
                .key_algorithms
                .get(keyid)
                .cloned()
                .unwrap_or_else(|| "ed25519".to_string()),
            bytes: bytes.clone(),
        })
    }

    /// Returns per-stream frontier `(seq, record_ref)` entries.
    pub fn stream_heads(&self) -> &std::collections::BTreeMap<String, (u64, String)> {
        &self.stream_heads
    }

    /// Stores a content-addressed blob and returns its `bytes:sha256:...` reference.
    pub fn put_blob(&mut self, raw: &[u8], media_type: Option<&str>) -> String {
        let r = bytes_ref(raw);
        self.blobs.entry(r.clone()).or_insert_with(|| {
            (
                BASE64_STANDARD.encode(raw),
                media_type.map(ToOwned::to_owned),
            )
        });
        r
    }

    /// Registers an Ed25519 public key in the bundle's `keys` array and returns its `KeyId`.
    pub fn register_ed25519_key(&mut self, verifying_key_bytes: &[u8; 32]) -> String {
        let keyid = ed25519_key_id(verifying_key_bytes);
        self.keys
            .entry(keyid.clone())
            .or_insert_with(|| BASE64_STANDARD.encode(verifying_key_bytes));
        self.key_algorithms
            .entry(keyid.clone())
            .or_insert_with(|| "ed25519".to_string());
        keyid
    }

    /// Registers an arbitrary Provenance v2 `PublicKeyEntry` (`ed25519`, `es256`, or `es384`).
    pub fn register_public_key_entry(&mut self, entry: &PublicKeyEntry) -> Result<(), String> {
        let alg = crate::crypto_keys::SignatureAlgorithm::parse(&entry.algorithm)?;
        self.keys
            .entry(entry.keyid.clone())
            .or_insert_with(|| entry.bytes.clone());
        self.key_algorithms
            .entry(entry.keyid.clone())
            .or_insert_with(|| alg.as_str().to_string());
        Ok(())
    }

    /// Appends a signed record onto `stream`, automatically assigning `seq` and `previous`.
    pub fn append_stream_record(
        &mut self,
        signers: &[&SigningKey],
        stream: &str,
        mut envelope_fields: Map<String, Value>,
    ) -> Result<SignedEndpointRecord, String> {
        for s in signers {
            self.register_ed25519_key(&s.verifying_key().to_bytes());
        }
        let (next_seq, prev_val) = match self.stream_heads.get(stream) {
            Some((seq, head_ref)) => (seq + 1, Value::String(head_ref.clone())),
            None => (1, Value::Null),
        };
        envelope_fields.insert("stream".to_string(), Value::String(stream.to_string()));
        envelope_fields.insert("seq".to_string(), Value::Number(next_seq.into()));
        envelope_fields.insert("previous".to_string(), prev_val);

        let signed = sign_v2_record_multi(signers, envelope_fields)?;
        self.stream_heads
            .insert(stream.to_string(), (next_seq, signed.record_ref.clone()));
        self.records.push(signed.clone());
        Ok(signed)
    }

    /// Exports the recorded streams, blobs, and keys as canonical `r5e.provenance-export/v2` JSON bytes.
    pub fn export_v2_bundle_bytes(&self, query: Value) -> Result<Vec<u8>, String> {
        let frontier: Vec<Value> = self
            .stream_heads
            .iter()
            .map(|(stream, (seq, event))| {
                serde_json::json!({
                    "stream": stream,
                    "seq": seq,
                    "event": event,
                })
            })
            .collect();

        let records: Vec<Value> = self
            .records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "ref": r.record_ref,
                    "envelope": r.envelope,
                })
            })
            .collect();

        let blobs: Vec<Value> = self
            .blobs
            .iter()
            .map(|(r, (b64, media_type))| {
                let mut m = Map::new();
                m.insert("ref".to_string(), Value::String(r.clone()));
                m.insert("base64".to_string(), Value::String(b64.clone()));
                if let Some(mt) = media_type {
                    m.insert("mediaType".to_string(), Value::String(mt.clone()));
                }
                Value::Object(m)
            })
            .collect();

        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|(keyid, b64)| {
                let alg = self
                    .key_algorithms
                    .get(keyid)
                    .map(String::as_str)
                    .unwrap_or("ed25519");
                serde_json::json!({
                    "keyid": keyid,
                    "algorithm": alg,
                    "bytes": b64,
                })
            })
            .collect();

        let bundle = serde_json::json!({
            "format": "r5e.provenance-export/v2",
            "scope": {
                "query": query,
                "at": frontier,
            },
            "records": records,
            "blobs": blobs,
            "keys": keys,
            "seals": [],
            "checkpoints": [],
            "proofs": [],
            "publicationProofs": [],
            "omissions": [],
        });

        encode_canonical_json(&bundle)
    }

    /// Imports pre-signed authority chain records, `DefinitionPublished` records, public keys,
    /// and capture-profile blobs returned by gateway `Badge` enrolment (`POST /api/v1/badges/finalize`),
    /// so the endpoint helper can emit self-contained `r5e.provenance-export/v2` bundles offline.
    pub fn ingest_enrolment_response(
        &mut self,
        resp: &FinalizedBadgeResponse,
    ) -> Result<(), String> {
        for key in &resp.keys {
            self.register_public_key_entry(key)?;
        }
        for blob in &resp.blobs {
            self.blobs
                .entry(blob.blob_ref.clone())
                .or_insert_with(|| (blob.base64.clone(), blob.media_type.clone()));
        }
        for rec in resp
            .publications
            .iter()
            .chain(resp.authority_chain.iter())
            .chain(std::iter::once(&resp.badge))
        {
            self.ingest_external_record(rec)?;
        }
        Ok(())
    }

    /// Appends an already-signed record (such as an upstream `Endorsement`, `DefinitionPublished`,
    /// or finalized `Badge`) and updates `stream_heads` for `scope.at`.
    pub fn ingest_external_record(&mut self, rec: &SignedEndpointRecord) -> Result<(), String> {
        if self.records.iter().any(|r| r.record_ref == rec.record_ref) {
            return Ok(());
        }
        let payload_bytes = BASE64_STANDARD
            .decode(&rec.envelope.payload)
            .map_err(|e| format!("invalid external record payload base64: {e}"))?;
        let parsed: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("invalid external record payload JSON: {e}"))?;
        if let (Some(stream), Some(seq)) = (
            parsed.get("stream").and_then(Value::as_str),
            parsed.get("seq").and_then(Value::as_u64),
        ) {
            let update = match self.stream_heads.get(stream) {
                Some((cur_seq, _)) => seq >= *cur_seq,
                None => true,
            };
            if update {
                self.stream_heads
                    .insert(stream.to_string(), (seq, rec.record_ref.clone()));
            }
        }
        self.records.push(rec.clone());
        Ok(())
    }
}

/// Public key entry in Provenance v2 wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyEntry {
    pub keyid: String,
    pub algorithm: String,
    pub bytes: String,
}

/// Content-addressed blob entry in Provenance v2 wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobEntry {
    #[serde(rename = "ref")]
    pub blob_ref: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "mediaType")]
    pub media_type: Option<String>,
    pub base64: String,
}

/// Step 1 request (`POST /v1/authority/badges/prepare`) from `r5e-endpoint-helper` to `recurse_gateway`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrepareBadgeRequest {
    #[serde(rename = "subjectKey")]
    pub subject_key: SubjectPublicKey,
    pub holder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    #[serde(rename = "requestedKinds")]
    pub requested_kinds: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "requestedActorPrefixes"
    )]
    pub requested_actor_prefixes: Option<Vec<String>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "requestedTtlSeconds"
    )]
    pub requested_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectPublicKey {
    pub algorithm: String,
    pub bytes: String,
}

/// Step 1 response (`200 OK`) carrying a stateless HMAC `ticket` and the unsigned canonical `Badge` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedBadgeResponse {
    pub ticket: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
}

/// Step 2 request (`POST /v1/authority/badges/finalize`) carrying `ticket`, `payload`, and Signer 2's signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeBadgeRequest {
    pub ticket: String,
    pub payload: String,
    #[serde(rename = "subjectSignature")]
    pub subject_signature: DsseSignature,
}

/// Step 2 response (`201 Created`) returning the 2-signature `Badge` plus the gateway's endorsement chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedBadgeResponse {
    pub badge: SignedEndpointRecord,
    #[serde(rename = "streamPrefix")]
    pub stream_prefix: String,
    #[serde(rename = "authorityChain")]
    pub authority_chain: Vec<SignedEndpointRecord>,
    #[serde(default)]
    pub publications: Vec<SignedEndpointRecord>,
    pub keys: Vec<PublicKeyEntry>,
    #[serde(default)]
    pub blobs: Vec<BlobEntry>,
}

impl SignedEndpointRecord {
    pub fn from_parts(record_ref: String, envelope: DsseEnvelope) -> Self {
        Self {
            record_ref,
            envelope,
        }
    }
}

/// Strict padded base64 decoder enforcing zero unused pad bits (`VERIFY-V2.md` §2.5).
pub fn decode_strict_base64(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("empty base64 string where strict base64 is required".to_string());
    }
    let decoded = BASE64_STANDARD
        .decode(input)
        .map_err(|e| format!("invalid base64: {e}"))?;
    if BASE64_STANDARD.encode(&decoded) != input {
        return Err("non-canonical base64 padding bits".to_string());
    }
    Ok(decoded)
}

/// Validates a gateway-prepared `Badge` draft BEFORE signing with `helper_key`, preventing a
/// compromised or buggy gateway from tricking the endpoint into co-signing a `Succession`,
/// wider kind grant, or longer TTL than requested, then produces Signer 2's `FinalizeBadgeRequest`.
pub fn counter_sign_prepared_badge(
    helper_key: &SigningKey,
    req: &PrepareBadgeRequest,
    prepared: &PreparedBadgeResponse,
) -> Result<FinalizeBadgeRequest, String> {
    if prepared.ticket.is_empty() {
        return Err("prepared badge missing stateless ticket".to_string());
    }
    if prepared.payload_type != PROVENANCE_V2_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected payloadType in prepared badge: {}",
            prepared.payload_type
        ));
    }
    let payload_bytes = decode_strict_base64(&prepared.payload)?;
    let parsed: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("prepared badge payload is not valid JSON: {e}"))?;
    let reencoded = encode_canonical_json(&parsed)?;
    if reencoded != payload_bytes {
        return Err("prepared badge payload is not canonical JSON (VERIFY-V2 §2.1)".to_string());
    }

    let api_version = parsed
        .get("apiVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = parsed
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if api_version != "provenance.r5e.io/v2" || kind != "Badge" {
        return Err(format!(
            "refusing to co-sign non-Badge record: {api_version}/{kind}"
        ));
    }

    let captured_at_str = parsed
        .get("capturedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared badge missing capturedAt".to_string())?;
    let captured_at = chrono::DateTime::parse_from_rfc3339(captured_at_str)
        .map_err(|e| format!("invalid capturedAt in prepared badge: {e}"))?
        .with_timezone(&chrono::Utc);

    let body = parsed
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared badge payload missing body object".to_string())?;

    let helper_pub_bytes = helper_key.verifying_key().to_bytes();
    let expected_subject = ed25519_key_id(&helper_pub_bytes);
    let expected_pub_b64 = BASE64_STANDARD.encode(helper_pub_bytes);

    let actual_subject = body
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual_subject != expected_subject {
        return Err(format!(
            "prepared badge subject mismatch: expected {expected_subject}, got {actual_subject}"
        ));
    }

    let subject_key = body
        .get("subjectKey")
        .and_then(Value::as_object)
        .ok_or_else(|| "prepared badge missing body.subjectKey".to_string())?;
    if subject_key.get("algorithm").and_then(Value::as_str) != Some("ed25519")
        || subject_key.get("bytes").and_then(Value::as_str) != Some(expected_pub_b64.as_str())
    {
        return Err(
            "prepared badge subjectKey does not match local endpoint public key".to_string(),
        );
    }

    let holder = body
        .get("holder")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if holder != req.holder {
        return Err(format!(
            "prepared badge holder mismatch: expected {}, got {holder}",
            req.holder
        ));
    }

    // Verify `body.kinds` is a non-empty subset of `req.requested_kinds`:
    let kinds_arr = body
        .get("kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "prepared badge missing body.kinds array".to_string())?;
    if kinds_arr.is_empty() {
        return Err("prepared badge body.kinds must be non-empty".to_string());
    }
    for k in kinds_arr {
        let ks = k
            .as_str()
            .ok_or_else(|| "prepared badge body.kinds contains non-string".to_string())?;
        if !req.requested_kinds.iter().any(|rk| rk == ks) {
            return Err(format!(
                "prepared badge granted unrequested kind {ks} outside requestedKinds"
            ));
        }
    }

    // Verify `[notBefore, notAfter]` ordering and `notAfter <= capturedAt + requestedTtlSeconds`:
    let not_before_str = body
        .get("notBefore")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared badge missing body.notBefore".to_string())?;
    let not_after_str = body
        .get("notAfter")
        .and_then(Value::as_str)
        .ok_or_else(|| "prepared badge missing body.notAfter".to_string())?;
    let not_before = chrono::DateTime::parse_from_rfc3339(not_before_str)
        .map_err(|e| format!("invalid body.notBefore: {e}"))?
        .with_timezone(&chrono::Utc);
    let not_after = chrono::DateTime::parse_from_rfc3339(not_after_str)
        .map_err(|e| format!("invalid body.notAfter: {e}"))?
        .with_timezone(&chrono::Utc);
    if not_before > not_after {
        return Err("prepared badge notBefore is after notAfter".to_string());
    }
    if let Some(ttl_secs) = req.requested_ttl_seconds {
        let max_not_after = captured_at + chrono::Duration::seconds(ttl_secs as i64);
        if not_after > max_not_after {
            return Err(format!(
                "prepared badge notAfter ({not_after_str}) exceeds capturedAt + requestedTtlSeconds ({ttl_secs}s)"
            ));
        }
    }

    let issuer = parsed
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if issuer.is_empty() || issuer == expected_subject {
        return Err("prepared badge issuer must be distinct gateway key".to_string());
    }

    let pae = dsse_pae(PROVENANCE_V2_PAYLOAD_TYPE, &payload_bytes);
    let sig = helper_key.sign(&pae);

    Ok(FinalizeBadgeRequest {
        ticket: prepared.ticket.clone(),
        payload: prepared.payload.clone(),
        subject_signature: DsseSignature {
            keyid: expected_subject,
            sig: BASE64_STANDARD.encode(sig.to_bytes()),
        },
    })
}

/// Base `schemaRef` for `provenance.r5e.io/v2/DefinitionPublished` (`api/provenance-vectors/definitions/index.json`).
pub const DEFINITION_PUBLISHED_SCHEMA_REF: &str =
    "bytes:sha256:3e83debc49b46aa26838559d0f33ba0fd225d305b792a20666f05716e0b209c9";

/// Base `schemaRef` for `provenance.r5e.io/v2/Observation` (`api/provenance-vectors/definitions/index.json`).
pub const OBSERVATION_SCHEMA_REF: &str =
    "bytes:sha256:382a10f48f2dd4f202b00c13459bce02bf243177e9f9ea1cfe14272b6542b157";

/// Base `schemaRef` for `provenance.r5e.io/v2/PayloadDisposition` (`api/provenance-vectors/definitions/index.json`).
pub const PAYLOAD_DISPOSITION_SCHEMA_REF: &str =
    "bytes:sha256:6c3afdfa4e5adb47188e5027ed671830a0e399e17705d97653e40cd5a637cce5";

/// Base `schemaRef` for `provenance.r5e.io/v2/RetentionHold` (`api/provenance-vectors/definitions/index.json`).
pub const RETENTION_HOLD_SCHEMA_REF: &str =
    "bytes:sha256:37d3d08f778c42f62685938e82cf2f0a3d185e574777ac1a83f6a12191c3443c";

/// Base `schemaRef` for `provenance.r5e.io/v2/RetentionHoldRelease` (`api/provenance-vectors/definitions/index.json`).
pub const RETENTION_HOLD_RELEASE_SCHEMA_REF: &str =
    "bytes:sha256:44e73b344f8c8b70ac5b73873c72dc9a0b35b7da6b2c841f870c3b093d145862";

/// Base `schemaRef` for `provenance.r5e.io/v2/Revocation` (`api/provenance-vectors/definitions/index.json`).
pub const REVOCATION_SCHEMA_REF: &str =
    "bytes:sha256:04a0eb543161e1d7d45e08e6f838bad52002aa3345a95aa6a19963055311d524";

/// Base `schemaRef` for `provenance.r5e.io/v2/RootsChanged` (`api/provenance-vectors/definitions/index.json`).
pub const ROOTS_CHANGED_SCHEMA_REF: &str =
    "bytes:sha256:44f32d8799989c7d8eb8afd734a59d8cd186c2b83ccec241d5dbb1eff3a11d98";

/// Base `schemaRef` for `provenance.r5e.io/v2/RootChangeApproval` (`api/provenance-vectors/definitions/index.json`).
pub const ROOT_CHANGE_APPROVAL_SCHEMA_REF: &str =
    "bytes:sha256:413277956c0e8e5ffa475a8c74abda264b4537653de2fcea93b3cb37ac4bc8db";

/// Base `schemaRef` for `provenance.r5e.io/v2/ToolCall` (`api/provenance-vectors/definitions/index.json`).
pub const TOOL_CALL_SCHEMA_REF: &str =
    "bytes:sha256:753c8b79b6ace378f9bc6b899564881c48cbef6c048608a37b1c6f7e4246c975";

/// Base `schemaRef` for `provenance.r5e.io/v2/ToolResult` (`api/provenance-vectors/definitions/index.json`).
pub const TOOL_RESULT_SCHEMA_REF: &str =
    "bytes:sha256:837142723e7ba7e5195fd8ca23352d7cccfc83374d872c4bbae9fb76f3c271a7";

/// Canonical base `schemaRef` map (`api/provenance-vectors/definitions/index.json`) for authoring
/// the endpoint helper's local `r5e.capture-profile/v2` blob.
pub fn base_v2_schema_map() -> Map<String, Value> {
    serde_json::json!({
        "core.r5e.io/v1/Artifact": "bytes:sha256:c0245e19bae4ad88907b86a9b714fb5b1d2359b600c6409a676c199d643e4dd4",
        "core.r5e.io/v1/KindDefinition": "bytes:sha256:c3d3d2feea558830c84b144179bce1ec045011b417e5d80548fd06e801ed3be4",
        "provenance.r5e.io/v2/Badge": "bytes:sha256:47de1ec5b6251304b14c43433b8208035a40733bfa8daeeb5ca00ba08c08df5f",
        "provenance.r5e.io/v2/ChainStarted": "bytes:sha256:8a2095f031e761d5dd606fdea9f1d6a5e4ca4c46860c621c2d7a51f3f3c3feb5",
        "provenance.r5e.io/v2/Checkpoint": "bytes:sha256:9b8cb0bd2245e80fee471a9fdc1083affd78cad61aaffd3b4a1a238745f8d820",
        "provenance.r5e.io/v2/DefinitionPublished": DEFINITION_PUBLISHED_SCHEMA_REF,
        "provenance.r5e.io/v2/Deployment": "bytes:sha256:f1f731b69ef1b43e56f7818ec19f0ba241dcb13e329810b28d5f726da4d11915",
        "provenance.r5e.io/v2/Disclosure": "bytes:sha256:b6941f90f798d87a63ad1a22520f1e836b7ea69980cecafbe729378740928e68",
        "provenance.r5e.io/v2/Endorsement": "bytes:sha256:db4c300394eb395309caf0a23fee82eb78486685e52c18ecad47a33ff03ca0b9",
        "provenance.r5e.io/v2/EpochSeal": "bytes:sha256:b0867d96e6bc35395dc0d78b8514cefe051d986a0f53f843d040918db4a5a5ad",
        "provenance.r5e.io/v2/ModelCall": "bytes:sha256:5b53d5dfadc42ed6c16fbd8cb1ac8759194240a67639abf2851032e3b44bd93c",
        "provenance.r5e.io/v2/ModelResponse": "bytes:sha256:147086a8b72c753bbe3c89bf63f3d3796a3b82221fa6165fea861d3a81f4af29",
        "provenance.r5e.io/v2/Observation": OBSERVATION_SCHEMA_REF,
        "provenance.r5e.io/v2/PayloadDisposition": PAYLOAD_DISPOSITION_SCHEMA_REF,
        "provenance.r5e.io/v2/PolicyDecision": "bytes:sha256:06fa7e3e4188200a1ee7668c544954cdad1e98f0a483e55b0b896d5a4f537ebf",
        "provenance.r5e.io/v2/Principal": "bytes:sha256:1c7539a0ae25c2bc1b9175a5a933d2d26122e588d8a210caa6ea6777d9996a01",
        "provenance.r5e.io/v2/PublishedView": "bytes:sha256:fd0f5356c43c275c61045d537b6b201fea38a154501eab3ec875a2190a0127fd",
        "provenance.r5e.io/v2/RetentionHold": RETENTION_HOLD_SCHEMA_REF,
        "provenance.r5e.io/v2/RetentionHoldRelease": RETENTION_HOLD_RELEASE_SCHEMA_REF,
        "provenance.r5e.io/v2/Revocation": REVOCATION_SCHEMA_REF,
        "provenance.r5e.io/v2/RootChangeApproval": ROOT_CHANGE_APPROVAL_SCHEMA_REF,
        "provenance.r5e.io/v2/RootsChanged": ROOTS_CHANGED_SCHEMA_REF,
        "provenance.r5e.io/v2/SessionClosed": "bytes:sha256:5feb99a5d12b59e513b61c81b377f215d1b1ad57e939ec159c654894e5f973b7",
        "provenance.r5e.io/v2/SessionOpened": "bytes:sha256:6d75de43a06d6e425759ef692b9bd5665e72c91ed5b2c2d7b4cb7df6048b4615",
        "provenance.r5e.io/v2/Succession": "bytes:sha256:f21f17796139f30c78601ac2b6c21b0549455752b3892b17de1c86512b3348a3",
        "provenance.r5e.io/v2/ToolCall": TOOL_CALL_SCHEMA_REF,
        "provenance.r5e.io/v2/ToolResult": TOOL_RESULT_SCHEMA_REF,
        "provenance.r5e.io/v2/Verification": "bytes:sha256:c6f76239086b22fe24cd6a311de6a45c17c2bdda4fd68a9d505bf31f92257cb2"
    })
    .as_object()
    .unwrap()
    .clone()
}

// ---------------------------------------------------------------------------
// A9 Base Definition Guards (`Details`, `Observation.topic`, `callId`, `ToolResult.call`)
// ---------------------------------------------------------------------------

pub const MAX_DETAILS_ENTRIES: usize = 64;
pub const MAX_DETAILS_VALUE_BYTES: usize = 2048;
pub const MAX_OBSERVATION_TOPIC_BYTES: usize = 128;
pub const MAX_CALL_ID_BYTES: usize = 256;

/// Truncates `s` at the largest valid UTF-8 character boundary `<= max_bytes`.
pub fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Checks A9 `Details` key pattern `^[A-Za-z][A-Za-z0-9_.-]{0,63}$`.
pub fn is_valid_detail_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Checks A9 `Observation.topic` pattern `^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$` (`<= 128` UTF-8 bytes).
pub fn is_valid_observation_topic(topic: &str) -> bool {
    if topic.is_empty() || topic.len() > MAX_OBSERVATION_TOPIC_BYTES {
        return false;
    }
    topic.split('.').all(|seg| {
        let bytes = seg.as_bytes();
        !bytes.is_empty()
            && bytes[0].is_ascii_lowercase()
            && bytes[1..]
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    })
}

/// Validates an A9 `Observation.topic` value.
pub fn validate_observation_topic(topic: &str, label: &str) -> Result<(), String> {
    if !is_valid_observation_topic(topic) {
        return Err(format!(
            "{label}: invalid Observation.topic {topic:?} (must match ^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)*$ and be <= {MAX_OBSERVATION_TOPIC_BYTES} UTF-8 bytes; A9 §2)"
        ));
    }
    Ok(())
}

/// Validates an A9 `ToolCall.body.callId` or `ToolResult.body.callId` (`1..=256` UTF-8 bytes).
pub fn validate_call_id(call_id: &str, label: &str) -> Result<(), String> {
    if call_id.is_empty() {
        return Err(format!(
            "{label}: callId must be non-empty when present (A9 §2)"
        ));
    }
    if call_id.len() > MAX_CALL_ID_BYTES {
        return Err(format!(
            "{label}: callId ({} UTF-8 bytes) exceeds maxLength {MAX_CALL_ID_BYTES} (A9 §2)",
            call_id.len()
        ));
    }
    Ok(())
}

fn flatten_a9_details_into(
    prefix: &str,
    map: &Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Result<(), String> {
    const MAX_SAFE_INT: i64 = (1_i64 << 53) - 1;
    for (k, v) in map {
        let full_key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            Value::Object(nested) => {
                if nested.is_empty() {
                    return Err(format!(
                        "details.{full_key}: empty nested object is not a valid A9 scalar detail"
                    ));
                }
                flatten_a9_details_into(&full_key, nested, out)?;
            }
            Value::Array(items) => {
                if !is_valid_detail_key(&full_key) {
                    return Err(format!(
                        "details key {full_key:?} violates A9 pattern ^[A-Za-z][A-Za-z0-9_.-]{{0,63}}$"
                    ));
                }
                let mut parts = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::String(s) => parts.push(s.clone()),
                        Value::Bool(b) => parts.push(b.to_string()),
                        Value::Number(n) => {
                            let i = n.as_i64().ok_or_else(|| {
                                format!("details.{full_key}: non-integer number in array")
                            })?;
                            if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
                                return Err(format!(
                                    "details.{full_key}: integer {i} outside ±(2^53 - 1)"
                                ));
                            }
                            parts.push(i.to_string());
                        }
                        _ => {
                            return Err(format!(
                                "details.{full_key}: nested array contains non-scalar element (move structured content behind contentRef; A9 §2)"
                            ));
                        }
                    }
                }
                let joined = parts.join(",");
                if joined.len() > MAX_DETAILS_VALUE_BYTES {
                    return Err(format!(
                        "details.{full_key}: flattened array ({} UTF-8 bytes) exceeds {MAX_DETAILS_VALUE_BYTES} bytes (move content behind contentRef; A9 §2)",
                        joined.len()
                    ));
                }
                out.insert(full_key, Value::String(joined));
            }
            Value::String(s) => {
                if !is_valid_detail_key(&full_key) {
                    return Err(format!(
                        "details key {full_key:?} violates A9 pattern ^[A-Za-z][A-Za-z0-9_.-]{{0,63}}$"
                    ));
                }
                if s.len() > MAX_DETAILS_VALUE_BYTES {
                    return Err(format!(
                        "details.{full_key}: string value ({} UTF-8 bytes) exceeds {MAX_DETAILS_VALUE_BYTES} bytes (move content behind contentRef; A9 §2)",
                        s.len()
                    ));
                }
                out.insert(full_key, Value::String(s.clone()));
            }
            Value::Bool(b) => {
                if !is_valid_detail_key(&full_key) {
                    return Err(format!(
                        "details key {full_key:?} violates A9 pattern ^[A-Za-z][A-Za-z0-9_.-]{{0,63}}$"
                    ));
                }
                out.insert(full_key, Value::Bool(*b));
            }
            Value::Number(n) => {
                if !is_valid_detail_key(&full_key) {
                    return Err(format!(
                        "details key {full_key:?} violates A9 pattern ^[A-Za-z][A-Za-z0-9_.-]{{0,63}}$"
                    ));
                }
                let i = n.as_i64().ok_or_else(|| {
                    format!("details.{full_key}: floats/out-of-range numbers are forbidden in A9 Details")
                })?;
                if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
                    return Err(format!(
                        "details.{full_key}: integer {i} outside ±(2^53 - 1)"
                    ));
                }
                out.insert(full_key, Value::Number(i.into()));
            }
            Value::Null => {
                return Err(format!(
                    "details.{full_key}: null is forbidden in A9 Details (expected string, integer, or boolean)"
                ));
            }
        }
    }
    Ok(())
}

/// Flattens nested objects (`a.b`) and scalar arrays (`"x,y"`) into flat A9 `Details` scalars and
/// validates key pattern (`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`), entry count (`<= 64`), and value sizes (`<= 2048` UTF-8 bytes).
pub fn normalize_a9_details(raw: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    flatten_a9_details_into("", raw, &mut out)?;
    validate_a9_details(&out, "details")?;
    Ok(out)
}

/// Strictly validates an already-flat A9 `Details` object without transforming nested containers.
pub fn validate_a9_details(details: &Map<String, Value>, label: &str) -> Result<(), String> {
    const MAX_SAFE_INT: i64 = (1_i64 << 53) - 1;
    if details.len() > MAX_DETAILS_ENTRIES {
        return Err(format!(
            "{label}: {} entries exceeds A9 maxEntries {MAX_DETAILS_ENTRIES}",
            details.len()
        ));
    }
    for (k, v) in details {
        if !is_valid_detail_key(k) {
            return Err(format!(
                "{label}: key {k:?} violates A9 pattern ^[A-Za-z][A-Za-z0-9_.-]{{0,63}}$"
            ));
        }
        match v {
            Value::Bool(_) => {}
            Value::Number(n) => {
                let i = n
                    .as_i64()
                    .ok_or_else(|| format!("{label}.{k}: non-integer number in A9 Details"))?;
                if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
                    return Err(format!("{label}.{k}: integer {i} outside ±(2^53 - 1)"));
                }
            }
            Value::String(s) => {
                if s.len() > MAX_DETAILS_VALUE_BYTES {
                    return Err(format!(
                        "{label}.{k}: string ({} UTF-8 bytes) exceeds {MAX_DETAILS_VALUE_BYTES} bytes",
                        s.len()
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "{label}.{k}: non-scalar value in A9 Details (expected string, integer, or boolean)"
                ));
            }
        }
    }
    Ok(())
}

/// Enforces A9 `Details`, `Observation.topic`, `ToolCall.callId` (promoting legacy `details.call_id` /
/// `details.callId` when top-level `callId` was omitted), and `ToolResult.call` / `ToolResult.callId`
/// invariants across every record authored by `r5e-endpoint-helper`.
pub fn validate_and_normalize_v2_body(short_kind: &str, body: &mut Value) -> Result<(), String> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| format!("{short_kind}.body must be a JSON object"))?;

    if short_kind == "ToolCall" && !obj.contains_key("callId") {
        let promoted = obj
            .get_mut("details")
            .and_then(Value::as_object_mut)
            .and_then(|det| {
                det.remove("callId")
                    .or_else(|| det.remove("call_id"))
                    .and_then(|v| match v {
                        Value::String(s) if !s.is_empty() => Some(s),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
            });
        if let Some(cid) = promoted {
            obj.insert("callId".to_string(), Value::String(cid));
        }
        if obj
            .get("details")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        {
            obj.remove("details");
        }
    }

    if matches!(short_kind, "ToolCall" | "ToolResult") {
        if let Some(cid_val) = obj.get("callId") {
            let cid = cid_val
                .as_str()
                .ok_or_else(|| format!("{short_kind}.body.callId must be a string"))?;
            validate_call_id(cid, &format!("{short_kind}.body.callId"))?;
        }
    }

    if short_kind == "ToolResult" {
        let call_ref = obj
            .get("call")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "ToolResult.body.call is required (must reference an admitted ToolCall evidence:sha256:<64hex>; A9 §2)".to_string()
            })?;
        if !crate::publication::is_valid_evidence_ref(call_ref) {
            return Err(format!(
                "ToolResult.body.call {call_ref:?} must match ^evidence:sha256:[0-9a-f]{{64}}$ (A9 §2)"
            ));
        }
    }

    if short_kind == "Observation" {
        let topic = obj
            .get("topic")
            .and_then(Value::as_str)
            .ok_or_else(|| "Observation.body.topic must be a string".to_string())?;
        validate_observation_topic(topic, "Observation.body.topic")?;
    }

    for unique_list_field in ["derivedFrom", "inputRefs", "outputRefs"] {
        if let Some(arr) = obj.get_mut(unique_list_field).and_then(Value::as_array_mut) {
            let mut deduped = Vec::with_capacity(arr.len());
            for item in arr.drain(..) {
                if !deduped.contains(&item) {
                    deduped.push(item);
                }
            }
            *arr = deduped;
        }
    }

    if let Some(det_val) = obj.get("details").cloned() {
        let det_map = det_val
            .as_object()
            .ok_or_else(|| format!("{short_kind}.body.details must be a JSON object"))?;
        let normalized = normalize_a9_details(det_map)?;
        obj.insert("details".to_string(), Value::Object(normalized));
    }

    Ok(())
}

/// Authoring model for an endpoint workload's canonical `r5e.capture-profile/v2` blob.
///
/// Mirrors the gateway's `"retention"` field verbatim during badge enrolment (`A8` §2.3)
/// unless explicitly overridden via `pub retention: Option<Value>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureProfile {
    pub stream_prefix: String,
    pub actor_prefixes: Vec<String>,
    pub issuer_keys: Vec<String>,
    pub sealer_keys: Vec<String>,
    #[serde(default)]
    pub checkpoint_keys: Vec<String>,
    pub failure_domain: String,
    pub required_payloads: String,
    pub on_failure: String,
    pub policy_required_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_policy_ref: Option<String>,
    /// Optional retention configuration (`{"disposal": "never"}` or
    /// `{"disposal": "by-record", "keepContentForSeconds": <u64>}`).
    /// When `None`, `"retention"` is omitted from the serialized `r5e.capture-profile/v2` JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<Value>,
}

impl CaptureProfile {
    pub fn to_profile_json(&self) -> Value {
        let mut doc = serde_json::json!({
            "format": "r5e.capture-profile/v2",
            "schemas": Value::Object(base_v2_schema_map()),
            "authority": {
                "bindings": [
                    {
                        "streamPrefix": &self.stream_prefix,
                        "actorPrefixes": &self.actor_prefixes,
                        "issuerKeys": &self.issuer_keys,
                        "sealerKeys": &self.sealer_keys,
                    }
                ],
                "checkpointKeys": &self.checkpoint_keys,
            },
            "durability": {
                "failureDomain": &self.failure_domain,
                "requiredPayloads": &self.required_payloads,
                "onFailure": &self.on_failure,
            },
            "policyRequiredKinds": &self.policy_required_kinds,
        });
        let obj = doc
            .as_object_mut()
            .expect("capture profile root must be object");
        if let Some(ref dpr) = self.deployment_policy_ref {
            obj.insert(
                "deploymentPolicyRef".to_string(),
                Value::String(dpr.clone()),
            );
        }
        if let Some(ref ret) = self.retention {
            obj.insert("retention".to_string(), ret.clone());
        }
        doc
    }

    pub fn encode_canonical(&self) -> Result<(String, Vec<u8>), String> {
        let doc = self.to_profile_json();
        let bytes = encode_canonical_json(&doc)?;
        Ok((bytes_ref(&bytes), bytes))
    }
}

/// Inspects `finalized.blobs` for the gateway's `CaptureProfile` blob (matching `badge_profile_ref`
/// first, then falling back to any `r5e.capture-profile/v2` or `r5e.capture-profile/v1` JSON blob)
/// and returns its `"retention"` value verbatim if present (`A8` §2.3).
pub fn extract_gateway_profile_retention(
    finalized: &FinalizedBadgeResponse,
    badge_profile_ref: Option<&str>,
) -> Result<Option<Value>, String> {
    if let Some(pref) = badge_profile_ref {
        if let Some(blob) = finalized.blobs.iter().find(|b| b.blob_ref == pref) {
            let decoded = decode_strict_base64(&blob.base64)
                .map_err(|e| format!("invalid base64 on gateway CaptureProfile {pref}: {e}"))?;
            let val: Value = serde_json::from_slice(&decoded)
                .map_err(|e| format!("invalid JSON on gateway CaptureProfile {pref}: {e}"))?;
            return Ok(val.get("retention").cloned());
        }
    }

    for blob in &finalized.blobs {
        let Ok(decoded) = decode_strict_base64(&blob.base64) else {
            continue;
        };
        let Ok(val) = serde_json::from_slice::<Value>(&decoded) else {
            continue;
        };
        let fmt_str = val.get("format").and_then(Value::as_str);
        if matches!(
            fmt_str,
            Some("r5e.capture-profile/v2") | Some("r5e.capture-profile/v1")
        ) {
            return Ok(val.get("retention").cloned());
        }
    }

    Ok(None)
}

/// Optional overrides when constructing an [`EnrolledEndpointSession`] from a finalized `Badge`.
#[derive(Debug, Clone, Default)]
pub struct EnrolledSessionOptions {
    /// When `Some(override_val)`, overrides the gateway profile's `"retention"` field
    /// (`Some(Some(v))` sets `"retention": v`; `Some(None)` omits `"retention"`).
    /// When `None`, copies `"retention"` verbatim from the gateway's `CaptureProfile` blob.
    pub retention_override: Option<Option<Value>>,
    /// Override `policyRequiredKinds` (defaults to `["provenance.r5e.io/v2/ToolCall"]` when `None`).
    pub policy_required_kinds: Option<Vec<String>>,
    /// Override `durability.requiredPayloads` (defaults to `"submitted-and-policy-inputs"` when `None`).
    pub required_payloads: Option<String>,
}

/// Active endpoint session backed by a gateway-enrolled 2-signature `Badge`.
///
/// Authors its own local `r5e.capture-profile/v2` blob over `stream_prefix` + `helper_keyid`
/// (copying `"retention"` verbatim from the gateway's `CaptureProfile` per `A8` §2.3),
/// ingests the gateway's endorsement chain, and automatically stamps `onBehalfOf = badge.actsFor`
/// (or omits `onBehalfOf` when `actsFor` is absent) per `A5` §3.
pub struct EnrolledEndpointSession {
    pub helper_key: SigningKey,
    pub helper_keyid: String,
    pub badge_ref: String,
    pub stream_prefix: String,
    pub acts_for: Option<String>,
    pub workload: Option<String>,
    pub actor_prefixes: Vec<String>,
    pub granted_kinds: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub retention: Option<Value>,
    pub capture_profile: CaptureProfile,
    pub local_profile_ref: String,
    pub deployment_policy_ref: String,
    pub recorder: EndpointBundleRecorder,
}

impl EnrolledEndpointSession {
    pub fn from_finalized(
        helper_key: SigningKey,
        finalize_req: &FinalizeBadgeRequest,
        finalized: &FinalizedBadgeResponse,
        cedar_policy_bytes: &[u8],
        actor_prefixes: &[String],
    ) -> Result<Self, String> {
        Self::from_finalized_with_options(
            helper_key,
            finalize_req,
            finalized,
            cedar_policy_bytes,
            actor_prefixes,
            &EnrolledSessionOptions::default(),
        )
    }

    pub fn from_finalized_with_options(
        helper_key: SigningKey,
        finalize_req: &FinalizeBadgeRequest,
        finalized: &FinalizedBadgeResponse,
        cedar_policy_bytes: &[u8],
        actor_prefixes: &[String],
        options: &EnrolledSessionOptions,
    ) -> Result<Self, String> {
        if finalized.badge.envelope.payload != finalize_req.payload {
            return Err("gateway finalize response altered badge payload bytes".to_string());
        }
        if finalized.badge.envelope.signatures.len() != 2 {
            return Err(format!(
                "expected 2 signatures on finalized Badge, got {}",
                finalized.badge.envelope.signatures.len()
            ));
        }
        if finalized.badge.envelope.signatures[1] != finalize_req.subject_signature {
            return Err(
                "finalized Badge second signature does not match helper signature".to_string(),
            );
        }

        let payload_bytes = decode_strict_base64(&finalized.badge.envelope.payload)?;
        let expected_ref = format!(
            "evidence:sha256:{}",
            crate::policy_gate::hex_lower(&Sha256::digest(&payload_bytes))
        );
        if finalized.badge.record_ref != expected_ref {
            return Err("finalized Badge ref does not match canonical payload digest".to_string());
        }
        let parsed: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("invalid finalized Badge JSON: {e}"))?;
        let badge_profile_ref = parsed.get("profileRef").and_then(Value::as_str);
        let body_obj = parsed.get("body");
        let acts_for = body_obj
            .and_then(|b| b.get("actsFor"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let workload = body_obj
            .and_then(|b| b.get("workload"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let not_before = body_obj
            .and_then(|b| b.get("notBefore"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let not_after = body_obj
            .and_then(|b| b.get("notAfter"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let granted_kinds: Vec<String> = body_obj
            .and_then(|b| b.get("kinds"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let badge_actor_prefixes: Option<Vec<String>> = body_obj
            .and_then(|b| b.get("actorPrefixes"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty());

        let gateway_retention = extract_gateway_profile_retention(finalized, badge_profile_ref)?;
        let effective_retention = match &options.retention_override {
            Some(explicit) => explicit.clone(),
            None => gateway_retention,
        };

        let helper_pub_bytes = helper_key.verifying_key().to_bytes();
        let helper_keyid = ed25519_key_id(&helper_pub_bytes);

        let mut recorder = EndpointBundleRecorder::new();
        recorder.register_ed25519_key(&helper_pub_bytes);
        recorder.ingest_enrolment_response(finalized)?;

        let deployment_policy_ref = recorder.put_blob(cedar_policy_bytes, Some("text/plain"));
        let effective_actor_prefixes: Vec<String> = badge_actor_prefixes.unwrap_or_else(|| {
            if actor_prefixes.is_empty() {
                vec!["urn:r5e:".to_string()]
            } else {
                actor_prefixes.to_vec()
            }
        });

        let capture_profile = CaptureProfile {
            stream_prefix: finalized.stream_prefix.clone(),
            actor_prefixes: effective_actor_prefixes.clone(),
            issuer_keys: vec![helper_keyid.clone()],
            sealer_keys: vec![helper_keyid.clone()],
            checkpoint_keys: Vec::new(),
            failure_domain: "managed-endpoint-local".to_string(),
            required_payloads: options
                .required_payloads
                .clone()
                .unwrap_or_else(|| "submitted-and-policy-inputs".to_string()),
            on_failure: "refuse".to_string(),
            policy_required_kinds: options
                .policy_required_kinds
                .clone()
                .unwrap_or_else(|| vec!["provenance.r5e.io/v2/ToolCall".to_string()]),
            deployment_policy_ref: Some(deployment_policy_ref.clone()),
            retention: effective_retention.clone(),
        };
        let (_, profile_bytes) = capture_profile.encode_canonical()?;
        let local_profile_ref = recorder.put_blob(&profile_bytes, Some("application/json"));

        Ok(Self {
            helper_key,
            helper_keyid,
            badge_ref: finalized.badge.record_ref.clone(),
            stream_prefix: finalized.stream_prefix.clone(),
            acts_for,
            workload,
            actor_prefixes: effective_actor_prefixes,
            granted_kinds,
            not_before,
            not_after,
            retention: effective_retention,
            capture_profile,
            local_profile_ref,
            deployment_policy_ref,
            recorder,
        })
    }

    /// Returns the workload's Ed25519 [`PublicKeyEntry`] in Provenance v2 wire format.
    pub fn public_key_entry(&self) -> PublicKeyEntry {
        let pub_bytes = self.helper_key.verifying_key().to_bytes();
        PublicKeyEntry {
            keyid: self.helper_keyid.clone(),
            algorithm: "ed25519".to_string(),
            bytes: BASE64_STANDARD.encode(pub_bytes),
        }
    }

    /// Appends a signed endpoint evidence record under `format!("{}{}", self.stream_prefix, stream_suffix)`,
    /// automatically stamping `profileRef`, `schemaRef` (looked up from base `definitions/index.json`),
    /// and `onBehalfOf = self.acts_for` when `acts_for` is present (`A5` §3).
    pub fn record_v2_event(
        &mut self,
        stream_suffix: &str,
        kind: &str,
        actor: &str,
        session: Option<&str>,
        captured_at: &str,
        mut body: Value,
    ) -> Result<SignedEndpointRecord, String> {
        let (kind_path, short_kind) =
            if let Some(short) = kind.strip_prefix("provenance.r5e.io/v2/") {
                (kind.to_string(), short.to_string())
            } else {
                (format!("provenance.r5e.io/v2/{kind}"), kind.to_string())
            };
        let schemas = base_v2_schema_map();
        let schema_ref = schemas
            .get(&kind_path)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("unknown base Provenance v2 kind: {kind_path}"))?;

        validate_and_normalize_v2_body(&short_kind, &mut body)?;

        let mut env = Map::new();
        env.insert(
            "apiVersion".to_string(),
            Value::String("provenance.r5e.io/v2".to_string()),
        );
        env.insert("kind".to_string(), Value::String(short_kind));
        env.insert(
            "schemaRef".to_string(),
            Value::String(schema_ref.to_string()),
        );
        env.insert(
            "profileRef".to_string(),
            Value::String(self.local_profile_ref.clone()),
        );
        env.insert("actor".to_string(), Value::String(actor.to_string()));
        if let Some(ref acts_for) = self.acts_for {
            env.insert("onBehalfOf".to_string(), Value::String(acts_for.clone()));
        }
        if let Some(sess) = session {
            env.insert("session".to_string(), Value::String(sess.to_string()));
        }
        env.insert(
            "capturedAt".to_string(),
            Value::String(captured_at.to_string()),
        );
        env.insert("body".to_string(), body);

        let full_stream = format!("{}{}", self.stream_prefix, stream_suffix);
        self.recorder
            .append_stream_record(&[&self.helper_key], &full_stream, env)
    }
}
