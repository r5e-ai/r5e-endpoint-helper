//! Authenticated at-rest encryption (`ChaCha20-Poly1305`, RFC 8439) and key-file hygiene for
//! the offline endpoint outbox (`--outbox-key-file` / `R5E_OUTBOX_KEY_FILE`).
//!
//! Security properties:
//! - Zero external crates beyond `Cargo.lock` (`sha2` + `base64` + OS CSPRNG).
//! - Constant-time RFC 8439 ChaCha20-Poly1305 AEAD verified against RFC 8439 §§2.4.2, 2.5.2,
//!   and 2.8.2 test vectors.
//! - Per-entry HMAC-SHA256 subkey derivation (`r5e-outbox-v1-subkey`) from a 128-bit random
//!   `entry_id` plus a fresh 96-bit OS-random nonce per write, eliminating random-nonce birthday
//!   bounds across arbitrarily many outbox updates.
//! - Role- and manifest-bound AAD: every `record` and `blob` ciphertext binds its role and
//!   `entry_id`, while the encrypted `meta` header binds the exact ordered list of `record` and
//!   `blob` entry IDs so record/blob deletion, reordering, splicing, or cross-slot swapping fails
//!   authentication immediately.
//! - Strict `0600` owner-only key file enforcement on Unix, redacted `Debug`, and volatile memory
//!   zeroization on drop.

use crate::attestation::{
    decode_strict_base64, encode_canonical_json, generate_os_random_bytes, BlobEntry,
    PublicKeyEntry, SignedEndpointRecord,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{compiler_fence, Ordering};

pub const OUTBOX_KEY_ENV_VAR: &str = "R5E_OUTBOX_KEY_FILE";
pub const ENCRYPTED_OUTBOX_QUEUE_FORMAT: &str = "r5e.endpoint-outbox-encrypted/v1";
pub const ENCRYPTED_OUTBOX_CIPHER: &str = "chacha20-poly1305";

const SUBKEY_DOMAIN_PREFIX: &[u8] = b"r5e-outbox-v1-subkey:";

fn zeroize_slice(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid aligned mutable reference within `buf`.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// 32-byte symmetric key for authenticated at-rest outbox encryption.
#[derive(Clone)]
pub struct OutboxKey {
    bytes: [u8; 32],
}

impl fmt::Debug for OutboxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutboxKey([REDACTED])")
    }
}

impl Drop for OutboxKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.bytes);
    }
}

impl OutboxKey {
    /// Constructs an [`OutboxKey`] from 32 raw bytes, rejecting all-zero keys.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        let mut non_zero = 0u8;
        for &b in &bytes {
            non_zero |= b;
        }
        if std::hint::black_box(non_zero) == 0 {
            return Err("refusing all-zero 32-byte outbox encryption key".to_string());
        }
        Ok(Self { bytes })
    }

    /// Generates a fresh 32-byte OS-random outbox key and writes it atomically with `0600`
    /// permissions (`O_EXCL` unless `force` is `true`).
    pub fn generate_to_file_0600(path: &Path, force: bool) -> Result<Self, String> {
        let mut raw = generate_os_random_bytes::<32>()?;
        let key_res = Self::from_bytes(raw);
        zeroize_slice(&mut raw);
        let key = key_res?;
        write_file_0600_durable(path, &key.bytes, force, "outbox key file")?;
        Ok(key)
    }

    /// Loads a 32-byte outbox key from `path` (accepting raw 32 bytes, 64 hex chars, or strict
    /// base64 decoding to 32 bytes). On Unix, refuses group- or world-accessible files (`mode & 0o077 != 0`).
    pub fn load_from_file_0600(path: &Path) -> Result<Self, String> {
        let sym_meta = fs::symlink_metadata(path)
            .map_err(|e| format!("cannot stat outbox key file {}: {e}", path.display()))?;
        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "refusing symlinked outbox key file {} (expected regular 0600 file)",
                path.display()
            ));
        }
        let meta = fs::metadata(path)
            .map_err(|e| format!("cannot read outbox key metadata {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!(
                "outbox key path {} is not a regular file",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                return Err(format!(
                    "outbox key file {} has insecure permissions {:04o} (must be 0600 owner-only)",
                    path.display(),
                    mode
                ));
            }
        }

        let mut raw = fs::read(path)
            .map_err(|e| format!("cannot read outbox key file {}: {e}", path.display()))?;
        let parsed = parse_outbox_key_material(&raw, path);
        zeroize_slice(&mut raw);
        parsed
    }
}

fn parse_outbox_key_material(raw: &[u8], path: &Path) -> Result<OutboxKey, String> {
    if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        let res = OutboxKey::from_bytes(arr);
        zeroize_slice(&mut arr);
        return res;
    }

    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut decoded = decode_hex(trimmed)?;
            if decoded.len() != 32 {
                zeroize_slice(&mut decoded);
                return Err("decoded hex outbox key is not 32 bytes".to_string());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            zeroize_slice(&mut decoded);
            let res = OutboxKey::from_bytes(arr);
            zeroize_slice(&mut arr);
            return res;
        }
        if !trimmed.is_empty() {
            if let Ok(mut b64_bytes) = decode_strict_base64(trimmed) {
                if b64_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b64_bytes);
                    zeroize_slice(&mut b64_bytes);
                    let res = OutboxKey::from_bytes(arr);
                    zeroize_slice(&mut arr);
                    return res;
                }
                zeroize_slice(&mut b64_bytes);
            }
        }
    }

    Err(format!(
        "invalid outbox key in {}: expected 32 raw bytes, 64 hex chars, or strict base64 of 32 bytes",
        path.display()
    ))
}

/// Resolves an optional [`OutboxKey`] from `--outbox-key-file` or `R5E_OUTBOX_KEY_FILE`.
pub fn resolve_optional_outbox_key(
    cli_key_file: Option<&Path>,
    env_var_name: &str,
) -> Result<Option<OutboxKey>, String> {
    if let Some(path) = cli_key_file {
        return OutboxKey::load_from_file_0600(path).map(Some);
    }
    if let Ok(env_val) = std::env::var(env_var_name) {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return OutboxKey::load_from_file_0600(Path::new(trimmed)).map(Some);
        }
    }
    Ok(None)
}

/// Writes `content` to `path` with strict `0600` permissions, `sync_all()` on the file, atomic
/// rename when `force` is `true` on an existing file, and best-effort `sync_all()` on the parent directory.
pub fn write_file_0600_durable(
    path: &Path,
    content: &[u8],
    force: bool,
    label: &str,
) -> Result<(), String> {
    if !force && path.exists() {
        return Err(format!(
            "refusing to overwrite existing {label} {} (pass --force to overwrite)",
            path.display()
        ));
    }
    let parent_dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            fs::create_dir_all(p)
                .map_err(|e| format!("cannot create parent directory for {label}: {e}"))?;
            p.to_path_buf()
        }
        _ => PathBuf::from("."),
    };

    if force {
        let rand_suffix = hex_lower(&generate_os_random_bytes::<8>()?);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("outbox-secret");
        let tmp_path = parent_dir.join(format!(".{file_name}.tmp.{rand_suffix}"));
        write_new_0600_sync(&tmp_path, content, label)?;
        if let Err(err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "cannot atomically replace {label} {}: {err}",
                path.display()
            ));
        }
        sync_dir_best_effort(&parent_dir);
        Ok(())
    } else {
        write_new_0600_sync(path, content, label)?;
        sync_dir_best_effort(&parent_dir);
        Ok(())
    }
}

fn write_new_0600_sync(path: &Path, content: &[u8], label: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let mut file = opts.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "refusing to overwrite existing {label} {} (pass --force to overwrite)",
                    path.display()
                )
            } else {
                format!("cannot create {label} {}: {e}", path.display())
            }
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            let _ = fs::remove_file(path);
            format!("cannot set 0600 permissions on {}: {e}", path.display())
        })?;
        if let Err(err) = file.write_all(content).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(path);
            return Err(format!("cannot write {label} {}: {err}", path.display()));
        }
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("cannot create {label} {}: {e}", path.display()))?;
        file.write_all(content)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("cannot write {label} {}: {e}", path.display()))?;
    }
    Ok(())
}

fn sync_dir_best_effort(dir: &Path) {
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = hex_nibble(bytes[idx])?;
        let lo = hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex digit".to_string()),
    }
}

/// HMAC-SHA256 (RFC 2104) used for domain-separated per-entry AEAD subkey derivation.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let mut inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out: [u8; 32] = outer.finalize().into();

    zeroize_slice(&mut ipad);
    zeroize_slice(&mut opad);
    zeroize_slice(&mut inner_hash);
    out
}

fn derive_entry_subkey(master_key: &OutboxKey, role: &str, entry_id: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(SUBKEY_DOMAIN_PREFIX.len() + role.len() + 1 + entry_id.len());
    info.extend_from_slice(SUBKEY_DOMAIN_PREFIX);
    info.extend_from_slice(role.as_bytes());
    info.push(b':');
    info.extend_from_slice(entry_id.as_bytes());
    hmac_sha256(&master_key.bytes, &info)
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// RFC 8439 §2.3 ChaCha20 block function.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let init: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let mut working = init;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);

        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (idx, word) in working.iter_mut().enumerate() {
        *word = word.wrapping_add(init[idx]);
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_le_bytes());
        *word = 0;
    }
    compiler_fence(Ordering::SeqCst);
    out
}

/// RFC 8439 §2.4 ChaCha20 stream cipher XOR starting at `initial_counter`.
pub fn chacha20_xor(
    key: &[u8; 32],
    initial_counter: u32,
    nonce: &[u8; 12],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    let blocks_needed = (input.len() as u64).div_ceil(64);
    if (initial_counter as u64).saturating_add(blocks_needed) > (u32::MAX as u64) + 1 {
        return Err("ChaCha20 plaintext exceeds 32-bit block counter limit".to_string());
    }

    let mut out = vec![0u8; input.len()];
    for (block_idx, (in_chunk, out_chunk)) in input.chunks(64).zip(out.chunks_mut(64)).enumerate() {
        let ctr = initial_counter.wrapping_add(block_idx as u32);
        let mut ks = chacha20_block(key, ctr, nonce);
        for (dst, (&src, &k)) in out_chunk.iter_mut().zip(in_chunk.iter().zip(ks.iter())) {
            *dst = src ^ k;
        }
        zeroize_slice(&mut ks);
    }
    Ok(out)
}

/// RFC 8439 §2.5 constant-time Poly1305 one-time MAC (`5 x 26`-bit limbs).
pub fn poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&otk[0..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let r_u128 = u128::from_le_bytes(r_bytes);
    zeroize_slice(&mut r_bytes);

    let r0 = (r_u128 & 0x3ff_ffff) as u64;
    let r1 = ((r_u128 >> 26) & 0x3ff_ffff) as u64;
    let r2 = ((r_u128 >> 52) & 0x3ff_ffff) as u64;
    let r3 = ((r_u128 >> 78) & 0x3ff_ffff) as u64;
    let r4 = ((r_u128 >> 104) & 0x3ff_ffff) as u64;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    for chunk in msg.chunks(16) {
        let mut buf = [0u8; 17];
        buf[..chunk.len()].copy_from_slice(chunk);
        buf[chunk.len()] = 1;

        let lo = u128::from_le_bytes(buf[0..16].try_into().expect("16-byte slice"));
        let hibit = (buf[16] as u64) << 24;
        zeroize_slice(&mut buf);

        h0 += (lo & 0x3ff_ffff) as u64;
        h1 += ((lo >> 26) & 0x3ff_ffff) as u64;
        h2 += ((lo >> 52) & 0x3ff_ffff) as u64;
        h3 += ((lo >> 78) & 0x3ff_ffff) as u64;
        h4 += ((lo >> 104) as u64) | hibit;

        let d0 = (h0 as u128) * (r0 as u128)
            + (h1 as u128) * (s4 as u128)
            + (h2 as u128) * (s3 as u128)
            + (h3 as u128) * (s2 as u128)
            + (h4 as u128) * (s1 as u128);
        let d1 = (h0 as u128) * (r1 as u128)
            + (h1 as u128) * (r0 as u128)
            + (h2 as u128) * (s4 as u128)
            + (h3 as u128) * (s3 as u128)
            + (h4 as u128) * (s2 as u128);
        let d2 = (h0 as u128) * (r2 as u128)
            + (h1 as u128) * (r1 as u128)
            + (h2 as u128) * (r0 as u128)
            + (h3 as u128) * (s4 as u128)
            + (h4 as u128) * (s3 as u128);
        let d3 = (h0 as u128) * (r3 as u128)
            + (h1 as u128) * (r2 as u128)
            + (h2 as u128) * (r1 as u128)
            + (h3 as u128) * (r0 as u128)
            + (h4 as u128) * (s4 as u128);
        let d4 = (h0 as u128) * (r4 as u128)
            + (h1 as u128) * (r3 as u128)
            + (h2 as u128) * (r2 as u128)
            + (h3 as u128) * (r1 as u128)
            + (h4 as u128) * (r0 as u128);

        let mut c = (d0 >> 26) as u64;
        h0 = (d0 as u64) & 0x3ff_ffff;
        let d1 = d1 + (c as u128);
        c = (d1 >> 26) as u64;
        h1 = (d1 as u64) & 0x3ff_ffff;
        let d2 = d2 + (c as u128);
        c = (d2 >> 26) as u64;
        h2 = (d2 as u64) & 0x3ff_ffff;
        let d3 = d3 + (c as u128);
        c = (d3 >> 26) as u64;
        h3 = (d3 as u64) & 0x3ff_ffff;
        let d4 = d4 + (c as u128);
        c = (d4 >> 26) as u64;
        h4 = (d4 as u64) & 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;
    }

    let mut c = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x3ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x3ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x3ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x3ff_ffff;
    let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    let inv = !mask;
    h0 = (h0 & inv) | g0;
    h1 = (h1 & inv) | g1;
    h2 = (h2 & inv) | g2;
    h3 = (h3 & inv) | g3;
    h4 = (h4 & inv) | g4;

    let h_u128 = (h0 as u128)
        | ((h1 as u128) << 26)
        | ((h2 as u128) << 52)
        | ((h3 as u128) << 78)
        | ((h4 as u128) << 104);
    let s_u128 = u128::from_le_bytes(otk[16..32].try_into().expect("16-byte pad slice"));
    h_u128.wrapping_add(s_u128).to_le_bytes()
}

fn build_poly1305_aead_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    let total = aad.len() + aad_pad + ciphertext.len() + ct_pad + 16;
    let mut mac_data = Vec::with_capacity(total);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + aad_pad, 0);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + ct_pad, 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac_data
}

fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for idx in 0..16 {
        diff |= a[idx] ^ b[idx];
    }
    std::hint::black_box(diff) == 0
}

/// RFC 8439 §2.8 `AEAD_CHACHA20_POLY1305` seal returning `ciphertext || 16-byte tag`.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    zeroize_slice(&mut block0);

    let mut ciphertext = chacha20_xor(key, 1, nonce, plaintext)?;
    let mac_input = build_poly1305_aead_input(aad, &ciphertext);
    let tag = poly1305_mac(&otk, &mac_input);
    zeroize_slice(&mut otk);

    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

/// RFC 8439 §2.8 `AEAD_CHACHA20_POLY1305` open verifying `16-byte tag` in constant time before
/// decrypting.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_and_tag.len() < 16 {
        return Err("truncated AEAD ciphertext (shorter than 16-byte Poly1305 tag)".to_string());
    }
    let ct_len = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let provided_tag: [u8; 16] = ciphertext_and_tag[ct_len..]
        .try_into()
        .expect("16-byte tag slice");

    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[0..32]);
    zeroize_slice(&mut block0);

    let mac_input = build_poly1305_aead_input(aad, ciphertext);
    let expected_tag = poly1305_mac(&otk, &mac_input);
    zeroize_slice(&mut otk);

    if !constant_time_eq_16(&expected_tag, &provided_tag) {
        return Err(
            "AEAD authentication tag mismatch (wrong outbox key or corrupted/tampered outbox entry)"
                .to_string(),
        );
    }

    chacha20_xor(key, 1, nonce, ciphertext)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedOutboxEntry {
    pub id: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EncryptedOutboxMetaPlaintext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<PublicKeyEntry>,
}

/// On-disk JSON representation for `r5e.endpoint-outbox-encrypted/v1`.
///
/// Zero plaintext URLs, keys, refs, or payload bytes appear on disk; every `record` and `blob`
/// sits in its own AEAD envelope, and `meta` authenticates the exact ordered manifest of `record`
/// and `blob` entry IDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedOutboxQueueFile {
    pub format: String,
    pub cipher: String,
    pub meta: EncryptedOutboxEntry,
    pub records: Vec<EncryptedOutboxEntry>,
    pub blobs: Vec<EncryptedOutboxEntry>,
}

fn validate_entry_id(id: &str) -> Result<(), String> {
    if id.len() != 32 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!(
            "invalid encrypted outbox entry id {id:?} (expected 32 lowercase hex chars)"
        ));
    }
    Ok(())
}

fn build_item_aad(role: &str, id: &str) -> Vec<u8> {
    format!("{ENCRYPTED_OUTBOX_QUEUE_FORMAT}|{role}|{id}").into_bytes()
}

fn build_meta_aad(meta_id: &str, record_ids: &[&str], blob_ids: &[&str]) -> Vec<u8> {
    let recs = record_ids.join(",");
    let blobs = blob_ids.join(",");
    format!("{ENCRYPTED_OUTBOX_QUEUE_FORMAT}|meta|{meta_id}|records:{recs}|blobs:{blobs}")
        .into_bytes()
}

fn seal_entry_bytes(
    master_key: &OutboxKey,
    role: &str,
    entry_id: String,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedOutboxEntry, String> {
    let mut subkey = derive_entry_subkey(master_key, role, &entry_id);
    let nonce = generate_os_random_bytes::<12>()?;
    let ct_res = chacha20_poly1305_encrypt(&subkey, &nonce, aad, plaintext);
    zeroize_slice(&mut subkey);
    let ct = ct_res?;
    Ok(EncryptedOutboxEntry {
        id: entry_id,
        nonce: BASE64_STANDARD.encode(nonce),
        ciphertext: BASE64_STANDARD.encode(ct),
    })
}

fn open_entry_bytes(
    master_key: &OutboxKey,
    role: &str,
    entry: &EncryptedOutboxEntry,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    validate_entry_id(&entry.id)?;
    let nonce_vec = decode_strict_base64(&entry.nonce).map_err(|e| {
        format!(
            "invalid base64 nonce on encrypted outbox {role} {}: {e}",
            entry.id
        )
    })?;
    let nonce: [u8; 12] = nonce_vec.try_into().map_err(|_| {
        format!(
            "invalid nonce length on encrypted outbox {role} {} (expected 12 bytes)",
            entry.id
        )
    })?;
    let ct_and_tag = decode_strict_base64(&entry.ciphertext).map_err(|e| {
        format!(
            "invalid base64 ciphertext on encrypted outbox {role} {}: {e}",
            entry.id
        )
    })?;

    let mut subkey = derive_entry_subkey(master_key, role, &entry.id);
    let pt_res = chacha20_poly1305_decrypt(&subkey, &nonce, aad, &ct_and_tag);
    zeroize_slice(&mut subkey);
    pt_res
}

/// Seals `(gateway_url, records, keys, blobs)` into an [`EncryptedOutboxQueueFile`].
pub fn encrypt_outbox_parts(
    key: &OutboxKey,
    gateway_url: Option<&str>,
    records: &[SignedEndpointRecord],
    keys: &[PublicKeyEntry],
    blobs: &[BlobEntry],
) -> Result<EncryptedOutboxQueueFile, String> {
    let mut enc_records = Vec::with_capacity(records.len());
    for rec in records {
        let id = hex_lower(&generate_os_random_bytes::<16>()?);
        let aad = build_item_aad("record", &id);
        let val = serde_json::to_value(rec)
            .map_err(|e| format!("serialize outbox record for encryption: {e}"))?;
        let mut pt = encode_canonical_json(&val)?;
        let sealed = seal_entry_bytes(key, "record", id, &aad, &pt);
        zeroize_slice(&mut pt);
        enc_records.push(sealed?);
    }

    let mut enc_blobs = Vec::with_capacity(blobs.len());
    for blob in blobs {
        let id = hex_lower(&generate_os_random_bytes::<16>()?);
        let aad = build_item_aad("blob", &id);
        let val = serde_json::to_value(blob)
            .map_err(|e| format!("serialize outbox blob for encryption: {e}"))?;
        let mut pt = encode_canonical_json(&val)?;
        let sealed = seal_entry_bytes(key, "blob", id, &aad, &pt);
        zeroize_slice(&mut pt);
        enc_blobs.push(sealed?);
    }

    let meta_id = hex_lower(&generate_os_random_bytes::<16>()?);
    let rec_ids: Vec<&str> = enc_records.iter().map(|e| e.id.as_str()).collect();
    let blob_ids: Vec<&str> = enc_blobs.iter().map(|e| e.id.as_str()).collect();
    let meta_aad = build_meta_aad(&meta_id, &rec_ids, &blob_ids);

    let meta_plain = EncryptedOutboxMetaPlaintext {
        gateway_url: gateway_url.map(ToOwned::to_owned),
        keys: keys.to_vec(),
    };
    let meta_val = serde_json::to_value(&meta_plain)
        .map_err(|e| format!("serialize outbox metadata for encryption: {e}"))?;
    let mut meta_pt = encode_canonical_json(&meta_val)?;
    let enc_meta = seal_entry_bytes(key, "meta", meta_id, &meta_aad, &meta_pt);
    zeroize_slice(&mut meta_pt);

    Ok(EncryptedOutboxQueueFile {
        format: ENCRYPTED_OUTBOX_QUEUE_FORMAT.to_string(),
        cipher: ENCRYPTED_OUTBOX_CIPHER.to_string(),
        meta: enc_meta?,
        records: enc_records,
        blobs: enc_blobs,
    })
}

/// Opens and authenticates an [`EncryptedOutboxQueueFile`] into
/// `(gateway_url, records, keys, blobs)`.
#[allow(clippy::type_complexity)]
pub fn decrypt_outbox_parts(
    key: &OutboxKey,
    encrypted: &EncryptedOutboxQueueFile,
) -> Result<
    (
        Option<String>,
        Vec<SignedEndpointRecord>,
        Vec<PublicKeyEntry>,
        Vec<BlobEntry>,
    ),
    String,
> {
    if encrypted.format != ENCRYPTED_OUTBOX_QUEUE_FORMAT {
        return Err(format!(
            "unexpected encrypted outbox format {:?}",
            encrypted.format
        ));
    }
    if encrypted.cipher != ENCRYPTED_OUTBOX_CIPHER {
        return Err(format!(
            "unsupported encrypted outbox cipher {:?} (expected {:?})",
            encrypted.cipher, ENCRYPTED_OUTBOX_CIPHER
        ));
    }

    let mut seen_rec_ids = std::collections::BTreeSet::new();
    for rec_entry in &encrypted.records {
        validate_entry_id(&rec_entry.id)?;
        if !seen_rec_ids.insert(rec_entry.id.as_str()) {
            return Err(format!(
                "duplicate encrypted outbox record entry id {:?}",
                rec_entry.id
            ));
        }
    }
    let mut seen_blob_ids = std::collections::BTreeSet::new();
    for blob_entry in &encrypted.blobs {
        validate_entry_id(&blob_entry.id)?;
        if !seen_blob_ids.insert(blob_entry.id.as_str()) {
            return Err(format!(
                "duplicate encrypted outbox blob entry id {:?}",
                blob_entry.id
            ));
        }
    }

    let rec_ids: Vec<&str> = encrypted.records.iter().map(|e| e.id.as_str()).collect();
    let blob_ids: Vec<&str> = encrypted.blobs.iter().map(|e| e.id.as_str()).collect();
    let meta_aad = build_meta_aad(&encrypted.meta.id, &rec_ids, &blob_ids);

    // Authenticate the manifest (`meta`) FIRST so any deleted, reordered, or spliced entry fails closed.
    let mut meta_pt = open_entry_bytes(key, "meta", &encrypted.meta, &meta_aad)?;
    let meta_res: Result<EncryptedOutboxMetaPlaintext, String> = serde_json::from_slice(&meta_pt)
        .map_err(|e| format!("corrupted decrypted outbox metadata JSON: {e}"));
    zeroize_slice(&mut meta_pt);
    let meta_parsed = meta_res?;

    let mut records = Vec::with_capacity(encrypted.records.len());
    for entry in &encrypted.records {
        let aad = build_item_aad("record", &entry.id);
        let mut pt = open_entry_bytes(key, "record", entry, &aad)?;
        let parsed: Result<SignedEndpointRecord, String> = serde_json::from_slice(&pt)
            .map_err(|e| format!("corrupted decrypted outbox record JSON: {e}"));
        zeroize_slice(&mut pt);
        records.push(parsed?);
    }

    let mut blobs = Vec::with_capacity(encrypted.blobs.len());
    for entry in &encrypted.blobs {
        let aad = build_item_aad("blob", &entry.id);
        let mut pt = open_entry_bytes(key, "blob", entry, &aad)?;
        let parsed: Result<BlobEntry, String> = serde_json::from_slice(&pt)
            .map_err(|e| format!("corrupted decrypted outbox blob JSON: {e}"));
        zeroize_slice(&mut pt);
        blobs.push(parsed?);
    }

    Ok((meta_parsed.gateway_url, records, meta_parsed.keys, blobs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_section_2_4_2_chacha20_encryption_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_hex = concat!(
            "6e2e359a2568f98041ba0728dd0d6981",
            "e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b357",
            "1639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e",
            "52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42",
            "874d"
        );
        let ct = chacha20_xor(&key, 1, &nonce, plaintext).unwrap();
        assert_eq!(hex_lower(&ct), expected_hex);
    }

    #[test]
    fn rfc8439_section_2_5_2_poly1305_vector() {
        let otk_hex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
        let otk: [u8; 32] = decode_hex(otk_hex).unwrap().try_into().unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(&otk, msg);
        assert_eq!(hex_lower(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn rfc8439_section_2_8_2_aead_chacha20_poly1305_vector() {
        let key_hex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        let key: [u8; 32] = decode_hex(key_hex).unwrap().try_into().unwrap();
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct_hex = concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "6116"
        );
        let expected_tag_hex = "1ae10b594f09e26a7e902ecbd0600691";

        let sealed = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(
            hex_lower(&sealed),
            format!("{expected_ct_hex}{expected_tag_hex}")
        );

        let opened = chacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());

        // AAD tamper fails closed:
        let mut bad_aad = aad;
        bad_aad[0] ^= 0x01;
        assert!(chacha20_poly1305_decrypt(&key, &nonce, &bad_aad, &sealed).is_err());

        // Tag tamper fails closed:
        let mut bad_tag = sealed.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x80;
        assert!(chacha20_poly1305_decrypt(&key, &nonce, &aad, &bad_tag).is_err());
    }
}
