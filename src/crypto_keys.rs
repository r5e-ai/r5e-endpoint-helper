//! Provenance v2 multi-algorithm public-key validation, key-ID derivation, ASN.1 DER / low-S
//! ECDSA normalization, and signature verification (`VERIFY-V2.md` §2.3 & `BLOCK-0.md`).
//!
//! Supports `ed25519`, `es256` (NIST P-256 / `secp256r1` over SHA-256), and `es384`
//! (NIST P-384 / `secp384r1` over SHA-384) with zero external crates beyond `Cargo.lock`.
//! Hardware signers (PIV tokens, `openssl dgst -sign`, PKCS#11, HSMs) emit ASN.1 DER
//! `ECDSA-Sig-Value` signatures whose `s` component exceeds `floor(n / 2)` ~50% of the time;
//! [`normalize_signature_bytes`] and [`parse_external_signature_bytes`] accept both raw `r || s`
//! and ASN.1 DER signatures and normalize `s > floor(n / 2)` to `n - s`.

use crate::attestation::decode_strict_base64;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
use std::cmp::Ordering;
use std::fmt;

/// Registered Provenance v2 signature algorithms (`VERIFY-V2.md` §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
    Es256,
    Es384,
}

impl SignatureAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Es256 => "es256",
            Self::Es384 => "es384",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "es256" | "p-256" | "p256" | "secp256r1" | "prime256v1" => Ok(Self::Es256),
            "es384" | "p-384" | "p384" | "secp384r1" => Ok(Self::Es384),
            other => Err(format!(
                "unsupported signature algorithm {other:?}: expected ed25519, es256, or es384"
            )),
        }
    }

    /// Canonical Provenance v2 public-key byte length (`32` for `ed25519`, `65` uncompressed SEC1
    /// for `es256`, `97` uncompressed SEC1 for `es384`).
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Es256 => 65,
            Self::Es384 => 97,
        }
    }

    /// Canonical Provenance v2 wire signature byte length (`64` for `ed25519` and `es256`, `96` for `es384`).
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Ed25519 | Self::Es256 => 64,
            Self::Es384 => 96,
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Exact 384-bit unsigned integer arithmetic (handles 255-bit, 256-bit, 384-bit)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct U384([u64; 6]); // little-endian limbs: 0[0] is least significant

impl U384 {
    const ZERO: Self = Self([0; 6]);
    const ONE: Self = Self([1, 0, 0, 0, 0, 0]);
    const TWO: Self = Self([2, 0, 0, 0, 0, 0]);
    const THREE: Self = Self([3, 0, 0, 0, 0, 0]);
    const FOUR: Self = Self([4, 0, 0, 0, 0, 0]);
    const EIGHT: Self = Self([8, 0, 0, 0, 0, 0]);

    fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    fn from_be_slice(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 48 {
            return Err(format!("integer exceeds 48 bytes ({} bytes)", bytes.len()));
        }
        let mut padded = [0u8; 48];
        padded[48 - bytes.len()..].copy_from_slice(bytes);
        let mut limbs = [0u64; 6];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = (5 - i) * 8;
            *limb = u64::from_be_bytes(padded[start..start + 8].try_into().unwrap());
        }
        Ok(Self(limbs))
    }

    fn to_be_bytes_len(self, out_len: usize) -> Vec<u8> {
        let mut full = [0u8; 48];
        for i in 0..6 {
            let start = (5 - i) * 8;
            full[start..start + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        full[48 - out_len..].to_vec()
    }

    fn cmp_val(&self, other: &Self) -> Ordering {
        for i in (0..6).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }

    fn bit(&self, idx: usize) -> bool {
        if idx >= 384 {
            return false;
        }
        ((self.0[idx / 64] >> (idx % 64)) & 1) == 1
    }

    fn wrapping_add(&self, rhs: &Self) -> (Self, bool) {
        let mut out = [0u64; 6];
        let mut carry = 0u128;
        for (o, (&a, &b)) in out.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            let sum = (a as u128) + (b as u128) + carry;
            *o = sum as u64;
            carry = sum >> 64;
        }
        (Self(out), carry != 0)
    }

    fn wrapping_sub(&self, rhs: &Self) -> (Self, bool) {
        let mut out = [0u64; 6];
        let mut borrow = 0u128;
        for (o, (&a, &b)) in out.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            let sub_rhs = (b as u128) + borrow;
            if (a as u128) >= sub_rhs {
                *o = (a as u128 - sub_rhs) as u64;
                borrow = 0;
            } else {
                *o = ((1u128 << 64) + (a as u128) - sub_rhs) as u64;
                borrow = 1;
            }
        }
        (Self(out), borrow != 0)
    }

    fn shl1_with_bit(&self, low_bit: u64) -> (Self, bool) {
        let mut out = [0u64; 6];
        let mut carry = low_bit & 1;
        for (o, &limb) in out.iter_mut().zip(self.0.iter()) {
            let next_carry = limb >> 63;
            *o = (limb << 1) | carry;
            carry = next_carry;
        }
        (Self(out), carry != 0)
    }

    fn add_mod(&self, rhs: &Self, m: &Self) -> Self {
        let (sum, overflow) = self.wrapping_add(rhs);
        if overflow || sum.cmp_val(m) != Ordering::Less {
            sum.wrapping_sub(m).0
        } else {
            sum
        }
    }

    fn sub_mod(&self, rhs: &Self, m: &Self) -> Self {
        if self.cmp_val(rhs) != Ordering::Less {
            self.wrapping_sub(rhs).0
        } else {
            let diff = rhs.wrapping_sub(self).0;
            m.wrapping_sub(&diff).0
        }
    }

    fn reduce_mod(wide: &[u64; 12], m: &Self) -> Self {
        let mut highest_limb = 11usize;
        while highest_limb > 0 && wide[highest_limb] == 0 {
            highest_limb -= 1;
        }
        if wide[highest_limb] == 0 {
            return Self::ZERO;
        }
        let top_bits = 64 - (wide[highest_limb].leading_zeros() as usize);
        let start_bit = highest_limb * 64 + top_bits - 1;

        let mut rem = Self::ZERO;
        for bit_idx in (0..=start_bit).rev() {
            let b = (wide[bit_idx / 64] >> (bit_idx % 64)) & 1;
            let (shifted, overflow) = rem.shl1_with_bit(b);
            rem = if overflow || shifted.cmp_val(m) != Ordering::Less {
                shifted.wrapping_sub(m).0
            } else {
                shifted
            };
        }
        rem
    }

    fn mod_of(&self, m: &Self) -> Self {
        if self.cmp_val(m) == Ordering::Less {
            *self
        } else {
            let mut wide = [0u64; 12];
            wide[..6].copy_from_slice(&self.0);
            Self::reduce_mod(&wide, m)
        }
    }

    fn mul_mod(&self, rhs: &Self, m: &Self) -> Self {
        let mut prod = [0u64; 12];
        for i in 0..6 {
            if self.0[i] == 0 {
                continue;
            }
            let mut carry = 0u128;
            for j in 0..6 {
                let acc = (prod[i + j] as u128) + (self.0[i] as u128) * (rhs.0[j] as u128) + carry;
                prod[i + j] = acc as u64;
                carry = acc >> 64;
            }
            prod[i + 6] = carry as u64;
        }
        Self::reduce_mod(&prod, m)
    }

    fn sqr_mod(&self, m: &Self) -> Self {
        self.mul_mod(self, m)
    }

    fn pow_mod(&self, exp: &Self, m: &Self) -> Self {
        let mut result = Self::ONE;
        let base = self.mod_of(m);
        let mut started = false;
        for bit_idx in (0..384).rev() {
            let b = exp.bit(bit_idx);
            if !started && !b {
                continue;
            }
            started = true;
            result = result.sqr_mod(m);
            if b {
                result = result.mul_mod(&base, m);
            }
        }
        result
    }

    /// Fermat modular inverse `self^(m - 2) mod m` for prime modulus `m`.
    fn inv_prime_mod(&self, m: &Self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let exp = m.wrapping_sub(&Self::TWO).0;
        Some(self.pow_mod(&exp, m))
    }
}

impl Ord for U384 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_val(other)
    }
}

impl PartialOrd for U384 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// Curve Parameters (NIST P-256 & NIST P-384)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct WeierstrassCurve {
    coord_len: usize,
    p: U384,
    a: U384,
    b: U384,
    gx: U384,
    gy: U384,
    n: U384,
    n_half: U384,
}

fn p256_curve() -> WeierstrassCurve {
    // NIST P-256 (secp256r1)
    let p = U384([
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
        0,
        0,
    ]);
    let a = p.wrapping_sub(&U384::THREE).0;
    let b = U384([
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
        0,
        0,
    ]);
    let gx = U384([
        0xf4a1_3945_d898_c296,
        0x7703_7d81_2deb_33a0,
        0xf8bc_e6e5_63a4_40f2,
        0x6b17_d1f2_e12c_4247,
        0,
        0,
    ]);
    let gy = U384([
        0xcbb6_4068_37bf_51f5,
        0x2bce_3357_6b31_5ece,
        0x8ee7_eb4a_7c0f_9e16,
        0x4fe3_42e2_fe1a_7f9b,
        0,
        0,
    ]);
    let n = U384([
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
        0,
        0,
    ]);
    let n_half = U384([
        0x79dc_e561_7e31_92a8,
        0xde73_7d56_d38b_cf42,
        0x7fff_ffff_ffff_ffff,
        0x7fff_ffff_8000_0000,
        0,
        0,
    ]);
    WeierstrassCurve {
        coord_len: 32,
        p,
        a,
        b,
        gx,
        gy,
        n,
        n_half,
    }
}

fn p384_curve() -> WeierstrassCurve {
    // NIST P-384 (secp384r1)
    let p = U384([
        0x0000_0000_ffff_ffff,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ]);
    let a = p.wrapping_sub(&U384::THREE).0;
    let b = U384([
        0x2a85_c8ed_d3ec_2aef,
        0xc656_398d_8a2e_d19d,
        0x0314_088f_5013_875a,
        0x181d_9c6e_fe81_4112,
        0x988e_056b_e3f8_2d19,
        0xb331_2fa7_e23e_e7e4,
    ]);
    let gx = U384([
        0x3a54_5e38_7276_0ab7,
        0x5502_f25d_bf55_296c,
        0x59f7_41e0_8254_2a38,
        0x6e1d_3b62_8ba7_9b98,
        0x8eb1_c71e_f320_ad74,
        0xaa87_ca22_be8b_0537,
    ]);
    let gy = U384([
        0x7a43_1d7c_90ea_0e5f,
        0x0a60_b1ce_1d7e_819d,
        0xe9da_3113_b5f0_b8c0,
        0xf8f4_1dbd_289a_147c,
        0x5d9e_98bf_9292_dc29,
        0x3617_de4a_9626_2c6f,
    ]);
    let n = U384([
        0xecec_196a_ccc5_2973,
        0x581a_0db2_48b0_a77a,
        0xc763_4d81_f437_2ddf,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ]);
    let n_half = U384([
        0x7676_0cb5_6662_94b9,
        0xac0d_06d9_2458_53bd,
        0xe3b1_a6c0_fa1b_96ef,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ]);
    WeierstrassCurve {
        coord_len: 48,
        p,
        a,
        b,
        gx,
        gy,
        n,
        n_half,
    }
}

#[derive(Clone, Copy)]
struct JacobianPoint {
    x: U384,
    y: U384,
    z: U384, // infinity iff z == 0
}

impl JacobianPoint {
    const INFINITY: Self = Self {
        x: U384::ZERO,
        y: U384::ONE,
        z: U384::ZERO,
    };

    fn from_affine(x: U384, y: U384) -> Self {
        Self { x, y, z: U384::ONE }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn to_affine(self, p: &U384) -> Option<(U384, U384)> {
        if self.is_infinity() {
            return None;
        }
        let z2 = self.z.sqr_mod(p);
        let z3 = z2.mul_mod(&self.z, p);
        let z2_inv = z2.inv_prime_mod(p)?;
        let z3_inv = z3.inv_prime_mod(p)?;
        Some((self.x.mul_mod(&z2_inv, p), self.y.mul_mod(&z3_inv, p)))
    }
}

fn point_double(pt: &JacobianPoint, curve: &WeierstrassCurve) -> JacobianPoint {
    if pt.is_infinity() || pt.y.is_zero() {
        return JacobianPoint::INFINITY;
    }
    let p = &curve.p;
    let x2 = pt.x.sqr_mod(p);
    let y2 = pt.y.sqr_mod(p);
    let y4 = y2.sqr_mod(p);
    let z2 = pt.z.sqr_mod(p);
    let z4 = z2.sqr_mod(p);

    // m = 3 * x^2 + a * z^4 mod p
    let three_x2 = U384::THREE.mul_mod(&x2, p);
    let a_z4 = curve.a.mul_mod(&z4, p);
    let m = three_x2.add_mod(&a_z4, p);

    // s = 4 * x * y^2 mod p
    let four_x = U384::FOUR.mul_mod(&pt.x, p);
    let s = four_x.mul_mod(&y2, p);

    // x3 = m^2 - 2 * s mod p
    let m2 = m.sqr_mod(p);
    let two_s = U384::TWO.mul_mod(&s, p);
    let x3 = m2.sub_mod(&two_s, p);

    // y3 = m * (s - x3) - 8 * y^4 mod p
    let s_minus_x3 = s.sub_mod(&x3, p);
    let m_term = m.mul_mod(&s_minus_x3, p);
    let eight_y4 = U384::EIGHT.mul_mod(&y4, p);
    let y3 = m_term.sub_mod(&eight_y4, p);

    // z3 = 2 * y * z mod p
    let two_y = U384::TWO.mul_mod(&pt.y, p);
    let z3 = two_y.mul_mod(&pt.z, p);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn point_add(p1: &JacobianPoint, p2: &JacobianPoint, curve: &WeierstrassCurve) -> JacobianPoint {
    if p1.is_infinity() {
        return *p2;
    }
    if p2.is_infinity() {
        return *p1;
    }
    let p = &curve.p;
    let z1_sq = p1.z.sqr_mod(p);
    let z2_sq = p2.z.sqr_mod(p);
    let u1 = p1.x.mul_mod(&z2_sq, p);
    let u2 = p2.x.mul_mod(&z1_sq, p);

    let z1_cu = z1_sq.mul_mod(&p1.z, p);
    let z2_cu = z2_sq.mul_mod(&p2.z, p);
    let s1 = p1.y.mul_mod(&z2_cu, p);
    let s2 = p2.y.mul_mod(&z1_cu, p);

    if u1 == u2 {
        if s1 == s2 {
            return point_double(p1, curve);
        }
        return JacobianPoint::INFINITY;
    }

    let h = u2.sub_mod(&u1, p);
    let r = s2.sub_mod(&s1, p);
    let h2 = h.sqr_mod(p);
    let h3 = h2.mul_mod(&h, p);
    let v = u1.mul_mod(&h2, p);

    // x3 = r^2 - h^3 - 2 * v mod p
    let r2 = r.sqr_mod(p);
    let two_v = U384::TWO.mul_mod(&v, p);
    let x3 = r2.sub_mod(&h3, p).sub_mod(&two_v, p);

    // y3 = r * (v - x3) - s1 * h^3 mod p
    let v_minus_x3 = v.sub_mod(&x3, p);
    let r_term = r.mul_mod(&v_minus_x3, p);
    let s1_h3 = s1.mul_mod(&h3, p);
    let y3 = r_term.sub_mod(&s1_h3, p);

    // z3 = z1 * z2 * h mod p
    let z1_z2 = p1.z.mul_mod(&p2.z, p);
    let z3 = z1_z2.mul_mod(&h, p);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn scalar_mul(pt: &JacobianPoint, k: &U384, curve: &WeierstrassCurve) -> JacobianPoint {
    let mut acc = JacobianPoint::INFINITY;
    let mut started = false;
    for bit_idx in (0..384).rev() {
        let b = k.bit(bit_idx);
        if !started && !b {
            continue;
        }
        started = true;
        acc = point_double(&acc, curve);
        if b {
            acc = point_add(&acc, pt, curve);
        }
    }
    acc
}

fn curve_rhs(x: &U384, curve: &WeierstrassCurve) -> U384 {
    let p = &curve.p;
    let x2 = x.sqr_mod(p);
    let x3 = x2.mul_mod(x, p);
    let ax = curve.a.mul_mod(x, p);
    x3.add_mod(&ax, p).add_mod(&curve.b, p)
}

fn validate_uncompressed_sec1_point(
    bytes: &[u8],
    curve: &WeierstrassCurve,
    label: &str,
) -> Result<(U384, U384), String> {
    let expected_len = 1 + 2 * curve.coord_len;
    if bytes.len() != expected_len || bytes[0] != 0x04 {
        return Err(format!(
            "{label}: expected {expected_len}-byte uncompressed SEC1 point (0x04 || X || Y)"
        ));
    }
    let x = U384::from_be_slice(&bytes[1..1 + curve.coord_len])?;
    let y = U384::from_be_slice(&bytes[1 + curve.coord_len..])?;
    if x >= curve.p || y >= curve.p {
        return Err(format!(
            "{label}: EC public key coordinate >= field modulus p"
        ));
    }
    let lhs = y.sqr_mod(&curve.p);
    let rhs = curve_rhs(&x, curve);
    if lhs != rhs {
        return Err(format!("{label}: EC public key point is not on curve"));
    }
    Ok((x, y))
}

/// Decompresses a compressed SEC1 point (`0x02`/`0x03 || X`) into canonical `0x04 || X || Y`.
fn decompress_sec1_point(
    bytes: &[u8],
    curve: &WeierstrassCurve,
    label: &str,
) -> Result<Vec<u8>, String> {
    let expected_len = 1 + curve.coord_len;
    if bytes.len() != expected_len || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(format!("{label}: invalid compressed SEC1 point"));
    }
    let odd_y = bytes[0] == 0x03;
    let x = U384::from_be_slice(&bytes[1..])?;
    if x >= curve.p {
        return Err(format!("{label}: compressed SEC1 X >= p"));
    }
    let rhs = curve_rhs(&x, curve);
    // Both P-256 and P-384 have p == 3 (mod 4), so sqrt(rhs) = rhs^((p + 1) / 4) mod p.
    // Since p = 4k + 3, (p + 1) / 4 = k + 1 = (p >> 2) + 1.
    let mut p_shr2 = [0u64; 6];
    for (i, item) in p_shr2.iter_mut().enumerate() {
        let hi = if i < 5 { curve.p.0[i + 1] << 62 } else { 0 };
        *item = (curve.p.0[i] >> 2) | hi;
    }
    let sqrt_exp = U384(p_shr2).wrapping_add(&U384::ONE).0;
    let mut y = rhs.pow_mod(&sqrt_exp, &curve.p);
    if y.sqr_mod(&curve.p) != rhs {
        return Err(format!("{label}: compressed SEC1 X has no point on curve"));
    }
    let y_is_odd = (y.0[0] & 1) == 1;
    if y_is_odd != odd_y {
        y = curve.p.wrapping_sub(&y).0;
    }
    let mut out = Vec::with_capacity(1 + 2 * curve.coord_len);
    out.push(0x04);
    out.extend_from_slice(&x.to_be_bytes_len(curve.coord_len));
    out.extend_from_slice(&y.to_be_bytes_len(curve.coord_len));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Ed25519 Strict Admissibility (`VERIFY-V2.md` §2.3)
// ---------------------------------------------------------------------------

const ED25519_SMALL_ORDER_CLEARED: [[u8; 32]; 5] = [
    [0x00; 32],
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Ed25519 group order `L = 2^252 + 27742317777372353535851937790883648493` in little-endian bytes.
const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn cmp_le_32(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    Ordering::Equal
}

/// Validates all 3 admissibility rules for an `ed25519` 32-byte public key (`VERIFY-V2.md` §2.3):
/// 1. `y < 2^255 - 19`
/// 2. With top bit cleared, not one of the 5 small-order points
/// 3. `(y^2 - 1) / (d * y^2 + 1) mod p` is 0 or a quadratic residue (and `x == 0` with sign bit 1 is rejected).
pub fn validate_ed25519_public_key_strict(bytes: &[u8], label: &str) -> Result<[u8; 32], String> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label}: Ed25519 public key must be 32 bytes"))?;
    let mut cleared = arr;
    let sign_bit = (arr[31] >> 7) & 1;
    cleared[31] &= 0x7f;

    // p = 2^255 - 19 in little-endian bytes:
    const ED25519_P_LE: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    if cmp_le_32(&cleared, &ED25519_P_LE) != Ordering::Less {
        return Err(format!(
            "{label}: inadmissible Ed25519 public key (y >= 2^255 - 19)"
        ));
    }
    if ED25519_SMALL_ORDER_CLEARED.contains(&cleared) {
        return Err(format!(
            "{label}: inadmissible Ed25519 small-order public key"
        ));
    }

    // Check Euler criterion on `(y^2 - 1) / (d * y^2 + 1) mod p` per VERIFY-V2 §2.3:
    let mut y_be = cleared;
    y_be.reverse();
    let mut p_be = ED25519_P_LE;
    p_be.reverse();
    let y = U384::from_be_slice(&y_be)?;
    let p = U384::from_be_slice(&p_be)?;

    let c121665 = U384([121_665, 0, 0, 0, 0, 0]);
    let c121666 = U384([121_666, 0, 0, 0, 0, 0]);
    let neg_121665 = p.sub_mod(&c121665, &p);
    let inv_121666 = c121666.inv_prime_mod(&p).expect("121666 invertible mod p");
    let d = neg_121665.mul_mod(&inv_121666, &p);

    let y2 = y.sqr_mod(&p);
    let num = y2.sub_mod(&U384::ONE, &p);
    let den = d.mul_mod(&y2, &p).add_mod(&U384::ONE, &p);
    let den_inv = den
        .inv_prime_mod(&p)
        .ok_or_else(|| format!("{label}: inadmissible Ed25519 point denominator 0"))?;
    let u = num.mul_mod(&den_inv, &p);

    if u.is_zero() {
        // u == 0 => x == 0; RFC 8032 §5.1.3 rejects x == 0 with sign_bit == 1, and y == 1 with sign_bit == 0
        // was already rejected in ED25519_SMALL_ORDER_CLEARED (`0100...` and `ecff...7f`).
        if sign_bit == 1 {
            return Err(format!(
                "{label}: invalid Ed25519 point (x == 0 with negative sign bit)"
            ));
        }
    } else {
        // (p - 1) / 2 = 2^254 - 10
        let p_minus_1 = p.wrapping_sub(&U384::ONE).0;
        let mut half_limbs = [0u64; 6];
        for (i, item) in half_limbs.iter_mut().enumerate() {
            let hi = if i < 5 { p_minus_1.0[i + 1] << 63 } else { 0 };
            *item = (p_minus_1.0[i] >> 1) | hi;
        }
        let legendre = u.pow_mod(&U384(half_limbs), &p);
        if legendre != U384::ONE {
            return Err(format!("{label}: Ed25519 public key is not on curve"));
        }
    }

    let vk = Ed25519VerifyingKey::from_bytes(&arr)
        .map_err(|e| format!("{label}: invalid Ed25519 curve point: {e}"))?;
    if vk.is_weak() {
        return Err(format!("{label}: weak Ed25519 public key"));
    }
    Ok(arr)
}

/// Validates public key bytes for `alg` (`VERIFY-V2.md` §2.3) and computes `key:<alg>:sha256:<64hex>`.
pub fn compute_key_id(alg: SignatureAlgorithm, public_key_bytes: &[u8]) -> Result<String, String> {
    validate_public_key_bytes(alg, public_key_bytes, "public_key")?;
    let tag = alg.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update([tag.len() as u8]);
    hasher.update(tag);
    hasher.update(public_key_bytes);
    let digest = hasher.finalize();
    Ok(format!(
        "key:{}:sha256:{}",
        alg.as_str(),
        crate::policy_gate::hex_lower(&digest)
    ))
}

/// Validates canonical public key bytes for `alg` per `VERIFY-V2.md` §2.3.
pub fn validate_public_key_bytes(
    alg: SignatureAlgorithm,
    public_key_bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    match alg {
        SignatureAlgorithm::Ed25519 => {
            validate_ed25519_public_key_strict(public_key_bytes, label)?;
            Ok(())
        }
        SignatureAlgorithm::Es256 => {
            validate_uncompressed_sec1_point(public_key_bytes, &p256_curve(), label)?;
            Ok(())
        }
        SignatureAlgorithm::Es384 => {
            validate_uncompressed_sec1_point(public_key_bytes, &p384_curve(), label)?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// SPKI / PEM / JSON / Base64 / Hex Public-Key Parsing
// ---------------------------------------------------------------------------

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

fn read_der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    if input.len() < 2 {
        return Err("truncated ASN.1 DER element".to_string());
    }
    let tag = input[0];
    let len_byte = input[1];
    let (len, hdr_len) = if (len_byte & 0x80) == 0 {
        (len_byte as usize, 2usize)
    } else {
        let count = (len_byte & 0x7f) as usize;
        if count == 0 || count > 3 || input.len() < 2 + count {
            return Err("invalid ASN.1 DER length encoding".to_string());
        }
        let mut n = 0usize;
        for &b in &input[2..2 + count] {
            n = (n << 8) | (b as usize);
        }
        if n < 128 || (count > 1 && input[2] == 0) {
            return Err("non-minimal ASN.1 DER length encoding".to_string());
        }
        (n, 2 + count)
    };
    if input.len() < hdr_len + len {
        return Err("ASN.1 DER element exceeds buffer".to_string());
    }
    Ok((tag, &input[hdr_len..hdr_len + len], &input[hdr_len + len..]))
}

fn parse_spki_der(der: &[u8], label: &str) -> Result<(SignatureAlgorithm, Vec<u8>), String> {
    let (seq_tag, seq_body, trailing) = read_der_tlv(der)?;
    if seq_tag != 0x30 || !trailing.is_empty() {
        return Err(format!("{label}: invalid SPKI DER outer SEQUENCE"));
    }
    let (alg_tag, alg_body, rest) = read_der_tlv(seq_body)?;
    if alg_tag != 0x30 {
        return Err(format!(
            "{label}: invalid SPKI AlgorithmIdentifier SEQUENCE"
        ));
    }
    let (bs_tag, bs_body, bs_rest) = read_der_tlv(rest)?;
    if bs_tag != 0x03 || !bs_rest.is_empty() || bs_body.is_empty() || bs_body[0] != 0x00 {
        return Err(format!("{label}: invalid SPKI subjectPublicKey BIT STRING"));
    }
    let key_bits = &bs_body[1..];

    if alg_body.starts_with(OID_ED25519) {
        let after_oid = &alg_body[OID_ED25519.len()..];
        if !after_oid.is_empty() {
            return Err(format!(
                "{label}: Ed25519 SPKI AlgorithmIdentifier must have absent parameters"
            ));
        }
        let arr = validate_ed25519_public_key_strict(key_bits, label)?;
        return Ok((SignatureAlgorithm::Ed25519, arr.to_vec()));
    }

    if alg_body.starts_with(OID_EC_PUBLIC_KEY) {
        let curve_oid = &alg_body[OID_EC_PUBLIC_KEY.len()..];
        let (alg, curve) = if curve_oid == OID_PRIME256V1 {
            (SignatureAlgorithm::Es256, p256_curve())
        } else if curve_oid == OID_SECP384R1 {
            (SignatureAlgorithm::Es384, p384_curve())
        } else {
            return Err(format!(
                "{label}: unsupported EC curve OID in SPKI (expected prime256v1 or secp384r1)"
            ));
        };
        let canonical_pub = if key_bits.len() == 1 + curve.coord_len
            && (key_bits[0] == 0x02 || key_bits[0] == 0x03)
        {
            decompress_sec1_point(key_bits, &curve, label)?
        } else {
            validate_uncompressed_sec1_point(key_bits, &curve, label)?;
            key_bits.to_vec()
        };
        return Ok((alg, canonical_pub));
    }

    Err(format!(
        "{label}: unsupported SPKI public key algorithm (expected Ed25519, P-256, or P-384)"
    ))
}

fn extract_pem_block(text: &str, begin: &str, end: &str) -> Option<String> {
    let start = text.find(begin)? + begin.len();
    let rest = &text[start..];
    let stop = rest.find(end)?;
    Some(
        rest[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    )
}

fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks_exact(2) {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        out.push(u8::from_str_radix(hex_str, 16).ok()?);
    }
    Some(out)
}

fn coerce_raw_pubkey_for_alg(
    alg: SignatureAlgorithm,
    candidate: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    if candidate.first() == Some(&0x30) {
        if let Ok((spki_alg, bytes)) = parse_spki_der(candidate, label) {
            if spki_alg != alg {
                return Err(format!(
                    "{label}: SPKI public key algorithm is {spki_alg}, expected {alg}"
                ));
            }
            return Ok(bytes);
        }
    }
    match alg {
        SignatureAlgorithm::Ed25519 => {
            let arr = validate_ed25519_public_key_strict(candidate, label)?;
            Ok(arr.to_vec())
        }
        SignatureAlgorithm::Es256 => {
            let curve = p256_curve();
            if candidate.len() == 33 && (candidate[0] == 0x02 || candidate[0] == 0x03) {
                decompress_sec1_point(candidate, &curve, label)
            } else {
                validate_uncompressed_sec1_point(candidate, &curve, label)?;
                Ok(candidate.to_vec())
            }
        }
        SignatureAlgorithm::Es384 => {
            let curve = p384_curve();
            if candidate.len() == 49 && (candidate[0] == 0x02 || candidate[0] == 0x03) {
                decompress_sec1_point(candidate, &curve, label)
            } else {
                validate_uncompressed_sec1_point(candidate, &curve, label)?;
                Ok(candidate.to_vec())
            }
        }
    }
}

/// Parses a public key (SPKI PEM, SPKI DER, uncompressed/compressed SEC1, raw 32B Ed25519,
/// `{algorithm, bytes}` JSON, base64, or hex), validates admissibility (`VERIFY-V2.md` §2.3),
/// and returns `(algorithm, canonical_public_key_bytes, key_id)`.
pub fn parse_public_key_material(
    expected_alg: Option<SignatureAlgorithm>,
    raw_bytes: &[u8],
    label: &str,
) -> Result<(SignatureAlgorithm, Vec<u8>, String), String> {
    if let Ok(text) = std::str::from_utf8(raw_bytes) {
        let trimmed = text.trim();
        if trimmed.contains("PRIVATE KEY-----") {
            return Err(format!(
                "{label} contains a PRIVATE key; pass only a public key"
            ));
        }
        if let Some(b64_body) = extract_pem_block(
            trimmed,
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
        ) {
            let der = BASE64_STANDARD
                .decode(&b64_body)
                .map_err(|e| format!("{label}: invalid SPKI PEM base64: {e}"))?;
            let (spki_alg, pub_bytes) = parse_spki_der(&der, label)?;
            if let Some(exp) = expected_alg {
                if spki_alg != exp {
                    return Err(format!(
                        "{label}: SPKI PEM key algorithm is {spki_alg}, expected {exp}"
                    ));
                }
            }
            let kid = compute_key_id(spki_alg, &pub_bytes)?;
            return Ok((spki_alg, pub_bytes, kid));
        }

        if trimmed.starts_with('{') {
            let val: Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("{label}: invalid public key JSON: {e}"))?;
            let pk_obj = val
                .get("publicKey")
                .unwrap_or(&val)
                .as_object()
                .ok_or_else(|| format!("{label}: expected JSON object for publicKey"))?;
            let alg_str = pk_obj
                .get("algorithm")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("{label}: missing string \"algorithm\" in publicKey JSON")
                })?;
            let json_alg = SignatureAlgorithm::parse(alg_str)?;
            if let Some(exp) = expected_alg {
                if json_alg != exp {
                    return Err(format!(
                        "{label}: JSON publicKey algorithm is {json_alg}, expected {exp}"
                    ));
                }
            }
            let b64 = pk_obj
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{label}: missing string \"bytes\" in publicKey JSON"))?;
            let decoded = decode_strict_base64(b64)
                .map_err(|e| format!("{label}: invalid strict base64 in publicKey JSON: {e}"))?;
            let pub_bytes = coerce_raw_pubkey_for_alg(json_alg, &decoded, label)?;
            let kid = compute_key_id(json_alg, &pub_bytes)?;
            if let Some(declared_id) = val
                .get("keyid")
                .or_else(|| val.get("key"))
                .and_then(Value::as_str)
            {
                if declared_id != kid {
                    return Err(format!(
                        "{label}: declared keyid ({declared_id}) does not match derived keyid ({kid})"
                    ));
                }
            }
            return Ok((json_alg, pub_bytes, kid));
        }
    }

    // Try raw binary / SPKI DER directly if length matches raw key or starts with ASN.1 SEQUENCE 0x30:
    if raw_bytes.first() == Some(&0x30) {
        if let Ok((spki_alg, pub_bytes)) = parse_spki_der(raw_bytes, label) {
            if let Some(exp) = expected_alg {
                if spki_alg != exp {
                    return Err(format!(
                        "{label}: SPKI DER algorithm is {spki_alg}, expected {exp}"
                    ));
                }
            }
            let kid = compute_key_id(spki_alg, &pub_bytes)?;
            return Ok((spki_alg, pub_bytes, kid));
        }
    }

    if let Some(alg) = expected_alg {
        if matches!(
            (alg, raw_bytes.len()),
            (SignatureAlgorithm::Ed25519, 32)
                | (SignatureAlgorithm::Es256, 65 | 33)
                | (SignatureAlgorithm::Es384, 97 | 49)
        ) {
            let pub_bytes = coerce_raw_pubkey_for_alg(alg, raw_bytes, label)?;
            let kid = compute_key_id(alg, &pub_bytes)?;
            return Ok((alg, pub_bytes, kid));
        }
    } else if raw_bytes.len() == 65 && raw_bytes[0] == 0x04 {
        let pub_bytes = coerce_raw_pubkey_for_alg(SignatureAlgorithm::Es256, raw_bytes, label)?;
        let kid = compute_key_id(SignatureAlgorithm::Es256, &pub_bytes)?;
        return Ok((SignatureAlgorithm::Es256, pub_bytes, kid));
    } else if raw_bytes.len() == 97 && raw_bytes[0] == 0x04 {
        let pub_bytes = coerce_raw_pubkey_for_alg(SignatureAlgorithm::Es384, raw_bytes, label)?;
        let kid = compute_key_id(SignatureAlgorithm::Es384, &pub_bytes)?;
        return Ok((SignatureAlgorithm::Es384, pub_bytes, kid));
    } else if raw_bytes.len() == 32 {
        let pub_bytes = coerce_raw_pubkey_for_alg(SignatureAlgorithm::Ed25519, raw_bytes, label)?;
        let kid = compute_key_id(SignatureAlgorithm::Ed25519, &pub_bytes)?;
        return Ok((SignatureAlgorithm::Ed25519, pub_bytes, kid));
    }

    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| format!("{label}: unrecognized binary public key format"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("{label}: public key input is empty"));
    }

    let decoded = if let Some(hex_bytes) = decode_hex_bytes(trimmed) {
        hex_bytes
    } else {
        let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        BASE64_STANDARD
            .decode(&clean)
            .map_err(|e| format!("{label}: invalid public key base64/PEM/hex: {e}"))?
    };

    if decoded.first() == Some(&0x30) {
        if let Ok((spki_alg, pub_bytes)) = parse_spki_der(&decoded, label) {
            if let Some(exp) = expected_alg {
                if spki_alg != exp {
                    return Err(format!(
                        "{label}: SPKI key algorithm is {spki_alg}, expected {exp}"
                    ));
                }
            }
            let kid = compute_key_id(spki_alg, &pub_bytes)?;
            return Ok((spki_alg, pub_bytes, kid));
        }
    }

    let alg = match expected_alg {
        Some(a) => a,
        None => match decoded.len() {
            32 => SignatureAlgorithm::Ed25519,
            65 | 33 => SignatureAlgorithm::Es256,
            97 | 49 => SignatureAlgorithm::Es384,
            other => {
                return Err(format!(
                    "{label}: cannot infer algorithm from {other}-byte key; pass --algorithm ed25519|es256|es384"
                ))
            }
        },
    };
    let pub_bytes = coerce_raw_pubkey_for_alg(alg, &decoded, label)?;
    let kid = compute_key_id(alg, &pub_bytes)?;
    Ok((alg, pub_bytes, kid))
}

/// Parses any supported public-key input (SPKI PEM/DER from `ykman piv keys export` or `openssl`,
/// `{algorithm, bytes}` JSON, uncompressed/compressed SEC1, raw 32B Ed25519, base64, or hex) into
/// a canonical `PublicKeyEntry` (`ed25519 | es256 | es384`).
pub fn parse_public_key_entry(
    raw_input: &[u8],
    expected_alg: Option<SignatureAlgorithm>,
    label: &str,
) -> Result<crate::attestation::PublicKeyEntry, String> {
    let (alg, pub_bytes, keyid) = parse_public_key_material(expected_alg, raw_input, label)?;
    Ok(crate::attestation::PublicKeyEntry {
        keyid,
        algorithm: alg.as_str().to_string(),
        bytes: BASE64_STANDARD.encode(&pub_bytes),
    })
}

/// Extracts and validates the trailing 64-character lowercase SHA-256 hex digest from any
/// `key:<alg>:sha256:<64hex>` identifier (`ed25519`, `es256`, `es384`, etc.).
pub fn key_id_sha256_hex(key_id: &str) -> Result<&str, String> {
    let Some(rest) = key_id.strip_prefix("key:") else {
        return Err(format!("invalid key ID {key_id:?}: missing 'key:' prefix"));
    };
    let Some((alg, hex)) = rest.split_once(":sha256:") else {
        return Err(format!(
            "invalid key ID {key_id:?}: expected 'key:<alg>:sha256:<64hex>'"
        ));
    };
    if alg.is_empty()
        || !alg
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "invalid key ID {key_id:?}: expected 'key:<alg>:sha256:<64 lowercase hex>'"
        ));
    }
    Ok(hex)
}

/// Maximum safe DSSE PAE byte length for PIV hardware `Ed25519` signing (smartcard PIV
/// `ED25519` refuses messages above ~3,072 bytes because pure EdDSA cannot pre-hash on the host).
pub const PIV_HARDWARE_ED25519_MAX_PAE_BYTES: usize = 3000;

/// Enforces the PIV hardware `Ed25519` PAE ceiling (`<= 3000` bytes), returning a
/// clear human-actionable error before an external PIV signer fails on message size.
pub fn check_piv_ed25519_pae_limit(alg: SignatureAlgorithm, pae_len: usize) -> Result<(), String> {
    if alg == SignatureAlgorithm::Ed25519 && pae_len > PIV_HARDWARE_ED25519_MAX_PAE_BYTES {
        return Err(format!(
            "PAE too long for PIV hardware Ed25519 (> {PIV_HARDWARE_ED25519_MAX_PAE_BYTES} bytes: {pae_len} bytes); split the endorsement or use es256"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ASN.1 DER `ECDSA-Sig-Value`, Low-S Normalization & Signature Verification
// ---------------------------------------------------------------------------

fn parse_der_positive_int(input: &[u8], coord_len: usize) -> Result<(Vec<u8>, &[u8]), String> {
    let (tag, body, rest) = read_der_tlv(input)?;
    if tag != 0x02 || body.is_empty() {
        return Err("expected non-empty ASN.1 DER INTEGER (0x02)".to_string());
    }
    if (body[0] & 0x80) != 0 {
        return Err("negative ASN.1 DER INTEGER in ECDSA signature".to_string());
    }
    if body.len() > 1 && body[0] == 0x00 && (body[1] & 0x80) == 0 {
        return Err("non-minimal leading zero in ASN.1 DER INTEGER".to_string());
    }
    let mag = if body[0] == 0x00 { &body[1..] } else { body };
    if mag.is_empty() || mag.iter().all(|&b| b == 0) {
        return Err("zero INTEGER in ECDSA signature".to_string());
    }
    if mag.len() > coord_len {
        return Err(format!(
            "ECDSA signature integer ({} bytes) exceeds {coord_len}-byte curve scalar size",
            mag.len()
        ));
    }
    let mut padded = vec![0u8; coord_len];
    padded[coord_len - mag.len()..].copy_from_slice(mag);
    Ok((padded, rest))
}

/// Parses an ASN.1 DER `ECDSA-Sig-Value` (`SEQUENCE { INTEGER r, INTEGER s }`) into fixed-width
/// `r || s` (`2 * coord_len` big-endian bytes, prior to low-S normalization).
pub fn parse_der_ecdsa_sig_raw(der: &[u8], coord_len: usize) -> Result<Vec<u8>, String> {
    let (seq_tag, seq_body, trailing) = read_der_tlv(der)?;
    if seq_tag != 0x30 || !trailing.is_empty() {
        return Err("invalid ASN.1 DER ECDSA-Sig-Value outer SEQUENCE".to_string());
    }
    let (r_bytes, after_r) = parse_der_positive_int(seq_body, coord_len)?;
    let (s_bytes, after_s) = parse_der_positive_int(after_r, coord_len)?;
    if !after_s.is_empty() {
        return Err("trailing bytes inside ASN.1 DER ECDSA-Sig-Value SEQUENCE".to_string());
    }
    let mut out = Vec::with_capacity(2 * coord_len);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    Ok(out)
}

/// Encodes `(r_be, s_be)` big-endian scalar slices into canonical ASN.1 DER `ECDSA-Sig-Value`.
pub fn encode_der_ecdsa_signature(r_be: &[u8], s_be: &[u8]) -> Result<Vec<u8>, String> {
    let encode_int = |raw: &[u8]| -> Result<Vec<u8>, String> {
        let first_nz = raw
            .iter()
            .position(|&b| b != 0)
            .ok_or_else(|| "ECDSA r/s integer cannot be zero".to_string())?;
        let trimmed = &raw[first_nz..];
        let needs_pad = (trimmed[0] & 0x80) != 0;
        let len = trimmed.len() + usize::from(needs_pad);
        if len >= 128 {
            return Err("ECDSA integer exceeds 127 bytes".to_string());
        }
        let mut out = Vec::with_capacity(2 + len);
        out.push(0x02);
        out.push(len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(trimmed);
        Ok(out)
    };
    let r_der = encode_int(r_be)?;
    let s_der = encode_int(s_be)?;
    let seq_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(3 + seq_len);
    out.push(0x30);
    if seq_len < 128 {
        out.push(seq_len as u8);
    } else {
        out.push(0x81);
        out.push(seq_len as u8);
    }
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    Ok(out)
}

fn normalize_raw_rs(raw_rs: &[u8], curve: &WeierstrassCurve) -> Result<(Vec<u8>, bool), String> {
    let clen = curve.coord_len;
    if raw_rs.len() != 2 * clen {
        return Err(format!(
            "expected {}-byte r || s ECDSA signature, got {} bytes",
            2 * clen,
            raw_rs.len()
        ));
    }
    let r = U384::from_be_slice(&raw_rs[..clen])?;
    let s = U384::from_be_slice(&raw_rs[clen..])?;
    if r.is_zero() || r >= curve.n {
        return Err("ECDSA signature r out of range [1, n - 1]".to_string());
    }
    if s.is_zero() || s >= curve.n {
        return Err("ECDSA signature s out of range [1, n - 1]".to_string());
    }
    let (low_s, flipped) = if s > curve.n_half {
        (curve.n.wrapping_sub(&s).0, true)
    } else {
        (s, false)
    };
    let mut out = Vec::with_capacity(2 * clen);
    out.extend_from_slice(&r.to_be_bytes_len(clen));
    out.extend_from_slice(&low_s.to_be_bytes_len(clen));
    Ok((out, flipped))
}

/// Normalizes an external `ed25519`, `es256`, or `es384` signature into canonical Provenance v2
/// wire bytes (`64` B for `ed25519` / `es256`, `96` B for `es384`):
/// - Accepts BOTH raw `r || s` (`64` B / `96` B) AND ASN.1 DER `ECDSA-Sig-Value` (PIV / `OpenSSL` / PKCS#11).
/// - Automatically normalizes high-`S` (`s > floor(n / 2)`) to `n - s` (`VERIFY-V2.md` §2.3).
/// - Returns `(canonical_sig_bytes, was_transformed)` where `was_transformed` is `true` if DER was
///   unwrapped and/or `s` was negated from high-`S` to low-`S`.
pub fn normalize_signature_bytes(
    alg: SignatureAlgorithm,
    sig_input: &[u8],
    verify_ctx: Option<(&[u8], &[u8])>, // Optional `(public_key_bytes, message_pae)`
) -> Result<(Vec<u8>, bool), String> {
    match alg {
        SignatureAlgorithm::Ed25519 => {
            if sig_input.len() != 64 {
                return Err(format!(
                    "Ed25519 signature must be 64 bytes, got {} bytes",
                    sig_input.len()
                ));
            }
            let s_le: [u8; 32] = sig_input[32..64].try_into().unwrap();
            if cmp_le_32(&s_le, &ED25519_L_LE) != Ordering::Less {
                return Err("Ed25519 signature S >= group order L (VERIFY-V2 §2.3)".to_string());
            }
            Ok((sig_input.to_vec(), false))
        }
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es384 => {
            let curve = if alg == SignatureAlgorithm::Es256 {
                p256_curve()
            } else {
                p384_curve()
            };
            let raw_len = 2 * curve.coord_len;

            if sig_input.len() == raw_len {
                // In the astronomically rare case (~2^-42) where a DER signature is also exactly
                // `raw_len` bytes, check DER vs raw `r || s` using `verify_ctx` if supplied.
                if sig_input[0] == 0x30 {
                    if let Ok(der_rs) = parse_der_ecdsa_sig_raw(sig_input, curve.coord_len) {
                        if let Ok((der_norm, _)) = normalize_raw_rs(&der_rs, &curve) {
                            if let Some((pub_bytes, msg)) = verify_ctx {
                                if verify_signature(alg, pub_bytes, msg, &der_norm).is_ok() {
                                    return Ok((der_norm, true));
                                }
                                let (raw_norm, flipped) = normalize_raw_rs(sig_input, &curve)?;
                                return Ok((raw_norm, flipped));
                            }
                            return Ok((der_norm, true));
                        }
                    }
                }
                return normalize_raw_rs(sig_input, &curve);
            }

            let der_rs = parse_der_ecdsa_sig_raw(sig_input, curve.coord_len).map_err(|e| {
                format!(
                    "invalid {alg} signature ({} bytes): expected {raw_len}-byte raw r||s or ASN.1 DER ECDSA-Sig-Value ({e})",
                    sig_input.len()
                )
            })?;
            let (norm, _) = normalize_raw_rs(&der_rs, &curve)?;
            Ok((norm, true))
        }
    }
}

/// Parses an external signature supplied from a file (which may contain raw binary DER / `r || s` /
/// 64B Ed25519, base64 text, or hex text) and normalizes it to canonical Provenance v2 wire bytes.
pub fn parse_external_signature_bytes(
    alg: SignatureAlgorithm,
    raw_file_or_text: &[u8],
    verify_ctx: Option<(&[u8], &[u8])>,
    label: &str,
) -> Result<(Vec<u8>, bool), String> {
    if raw_file_or_text.is_empty() {
        return Err(format!("{label}: signature input is empty"));
    }

    // 1. Try direct binary signature first (`r || s`, 64B Ed25519, or binary ASN.1 DER):
    if let Ok((norm, transformed)) = normalize_signature_bytes(alg, raw_file_or_text, verify_ctx) {
        if let Some((pub_bytes, msg)) = verify_ctx {
            if verify_signature(alg, pub_bytes, msg, &norm).is_ok() {
                return Ok((norm, transformed));
            }
        } else {
            return Ok((norm, transformed));
        }
    }

    // 2. Try UTF-8 text (base64 or hex):
    if let Ok(text) = std::str::from_utf8(raw_file_or_text) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            if let Some(hex_bytes) = decode_hex_bytes(trimmed) {
                return normalize_signature_bytes(alg, &hex_bytes, verify_ctx)
                    .map_err(|e| format!("{label}: {e}"));
            }
            let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(b64_bytes) = BASE64_STANDARD.decode(&clean) {
                return normalize_signature_bytes(alg, &b64_bytes, verify_ctx)
                    .map_err(|e| format!("{label}: {e}"));
            }
        }
    }

    // 3. Re-run binary normalization to surface the most specific structural error:
    normalize_signature_bytes(alg, raw_file_or_text, verify_ctx)
        .map_err(|e| format!("{label}: {e}"))
}

fn verify_ecdsa_low_s(
    public_key_bytes: &[u8],
    digest_bytes: &[u8],
    canonical_sig: &[u8],
    curve: &WeierstrassCurve,
    label: &str,
) -> Result<(), String> {
    let clen = curve.coord_len;
    if canonical_sig.len() != 2 * clen {
        return Err(format!(
            "{label}: signature must be {} bytes (r || s), got {} bytes",
            2 * clen,
            canonical_sig.len()
        ));
    }
    let (qx, qy) = validate_uncompressed_sec1_point(public_key_bytes, curve, label)?;
    let r = U384::from_be_slice(&canonical_sig[..clen])?;
    let s = U384::from_be_slice(&canonical_sig[clen..])?;
    if r.is_zero() || r >= curve.n {
        return Err(format!("{label}: ECDSA r out of range [1, n - 1]"));
    }
    if s.is_zero() || s > curve.n_half {
        return Err(format!(
            "{label}: ECDSA s violates low-S rule (must satisfy 1 <= s <= floor(n / 2))"
        ));
    }

    let z = U384::from_be_slice(digest_bytes)?.mod_of(&curve.n);
    let w = s
        .inv_prime_mod(&curve.n)
        .ok_or_else(|| format!("{label}: non-invertible ECDSA s"))?;
    let u1 = z.mul_mod(&w, &curve.n);
    let u2 = r.mul_mod(&w, &curve.n);

    let g = JacobianPoint::from_affine(curve.gx, curve.gy);
    let q = JacobianPoint::from_affine(qx, qy);
    let p1 = scalar_mul(&g, &u1, curve);
    let p2 = scalar_mul(&q, &u2, curve);
    let sum = point_add(&p1, &p2, curve);
    let (rx, _) = sum
        .to_affine(&curve.p)
        .ok_or_else(|| format!("{label}: ECDSA verification point is infinity"))?;
    let v = rx.mod_of(&curve.n);
    if v != r {
        return Err(format!("{label}: ECDSA signature verification failed"));
    }
    Ok(())
}

/// Cryptographically verifies a canonical Provenance v2 signature (`ed25519`, `es256`, or `es384`)
/// over `message` (`VERIFY-V2.md` §§2.3–2.4), enforcing strict public-key admissibility and low-`S`.
pub fn verify_signature(
    alg: SignatureAlgorithm,
    public_key_bytes: &[u8],
    message: &[u8],
    canonical_sig: &[u8],
) -> Result<(), String> {
    match alg {
        SignatureAlgorithm::Ed25519 => {
            let pub_arr = validate_ed25519_public_key_strict(public_key_bytes, "ed25519 verify")?;
            let sig_arr: [u8; 64] = canonical_sig
                .try_into()
                .map_err(|_| "Ed25519 signature must be 64 bytes".to_string())?;
            let s_le: [u8; 32] = sig_arr[32..64].try_into().unwrap();
            if cmp_le_32(&s_le, &ED25519_L_LE) != Ordering::Less {
                return Err("Ed25519 signature S >= L".to_string());
            }
            let vk = Ed25519VerifyingKey::from_bytes(&pub_arr)
                .map_err(|e| format!("invalid Ed25519 key: {e}"))?;
            let sig = Ed25519Signature::from_bytes(&sig_arr);
            vk.verify_strict(message, &sig)
                .map_err(|e| format!("Ed25519 signature verification failed: {e}"))
        }
        SignatureAlgorithm::Es256 => {
            let digest = Sha256::digest(message);
            verify_ecdsa_low_s(
                public_key_bytes,
                &digest,
                canonical_sig,
                &p256_curve(),
                "es256 verify",
            )
        }
        SignatureAlgorithm::Es384 => {
            let digest = Sha384::digest(message);
            verify_ecdsa_low_s(
                public_key_bytes,
                &digest,
                canonical_sig,
                &p384_curve(),
                "es384 verify",
            )
        }
    }
}

/// Encodes a validated public key into an RFC 5280 / RFC 8410 / RFC 5480 `SubjectPublicKeyInfo` PEM.
pub fn encode_spki_public_key_pem(
    alg: SignatureAlgorithm,
    public_key_bytes: &[u8],
) -> Result<String, String> {
    validate_public_key_bytes(alg, public_key_bytes, "encode_spki_public_key_pem")?;
    let der = match alg {
        SignatureAlgorithm::Ed25519 => {
            let mut v = Vec::with_capacity(44);
            v.extend_from_slice(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ]);
            v.extend_from_slice(public_key_bytes);
            v
        }
        SignatureAlgorithm::Es256 => {
            // 91-byte SPKI for uncompressed P-256 (65B)
            let mut v = Vec::with_capacity(91);
            v.extend_from_slice(&[
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ]);
            v.extend_from_slice(public_key_bytes);
            v
        }
        SignatureAlgorithm::Es384 => {
            // 120-byte SPKI for uncompressed P-384 (97B)
            let mut v = Vec::with_capacity(120);
            v.extend_from_slice(&[
                0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
            ]);
            v.extend_from_slice(public_key_bytes);
            v
        }
    };
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        BASE64_STANDARD.encode(&der)
    ))
}

/// Deterministic test-vector ECDSA helpers (used ONLY in unit & integration tests to synthesize
/// guaranteed high-`S` (`s > floor(n / 2)`) and low-`S` ASN.1 DER signatures for `ES256` and `ES384`).
#[doc(hidden)]
pub mod test_support {
    use super::*;

    fn curve_for(alg: SignatureAlgorithm) -> Result<WeierstrassCurve, String> {
        match alg {
            SignatureAlgorithm::Es256 => Ok(p256_curve()),
            SignatureAlgorithm::Es384 => Ok(p384_curve()),
            SignatureAlgorithm::Ed25519 => Err("expected Es256 or Es384".to_string()),
        }
    }

    pub fn derive_ecdsa_public_key_uncompressed(
        alg: SignatureAlgorithm,
        secret_scalar_be: &[u8],
    ) -> Result<Vec<u8>, String> {
        let curve = curve_for(alg)?;
        let d = U384::from_be_slice(secret_scalar_be)?;
        if d.is_zero() || d >= curve.n {
            return Err("ECDSA secret scalar out of range [1, n - 1]".to_string());
        }
        let g = JacobianPoint::from_affine(curve.gx, curve.gy);
        let q = scalar_mul(&g, &d, &curve);
        let (qx, qyi) = q
            .to_affine(&curve.p)
            .ok_or_else(|| "derived infinity".to_string())?;
        let mut out = Vec::with_capacity(1 + 2 * curve.coord_len);
        out.push(0x04);
        out.extend_from_slice(&qx.to_be_bytes_len(curve.coord_len));
        out.extend_from_slice(&qyi.to_be_bytes_len(curve.coord_len));
        Ok(out)
    }

    /// Deterministic ECDSA test signing returning `(low_s_raw_rs, high_s_der)`.
    /// Specifically constructs `high_s = n - low_s > floor(n / 2)` encoded as ASN.1 DER
    /// `ECDSA-Sig-Value` so hardware / OpenSSL high-`S` normalization is deterministically exercised!
    pub fn sign_ecdsa_with_high_s_der(
        alg: SignatureAlgorithm,
        secret_scalar_be: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let curve = curve_for(alg)?;
        let clen = curve.coord_len;
        let d = U384::from_be_slice(secret_scalar_be)?;
        if d.is_zero() || d >= curve.n {
            return Err("ECDSA secret scalar out of range [1, n - 1]".to_string());
        }
        let z = match alg {
            SignatureAlgorithm::Es256 => U384::from_be_slice(&Sha256::digest(message))?,
            SignatureAlgorithm::Es384 => U384::from_be_slice(&Sha384::digest(message))?,
            SignatureAlgorithm::Ed25519 => unreachable!(),
        }
        .mod_of(&curve.n);

        for ctr in 1u32..1000 {
            let mut h = Sha384::new();
            h.update(b"r5e-test-ecdsa-nonce:");
            h.update(secret_scalar_be);
            h.update(ctr.to_be_bytes());
            h.update(message);
            let k_raw = h.finalize();
            let k = U384::from_be_slice(&k_raw[..clen])?.mod_of(&curve.n);
            if k.is_zero() {
                continue;
            }
            let g = JacobianPoint::from_affine(curve.gx, curve.gy);
            let Some((rx, _)) = scalar_mul(&g, &k, &curve).to_affine(&curve.p) else {
                continue;
            };
            let r = rx.mod_of(&curve.n);
            if r.is_zero() {
                continue;
            }
            let Some(k_inv) = k.inv_prime_mod(&curve.n) else {
                continue;
            };
            let rd = r.mul_mod(&d, &curve.n);
            let z_plus_rd = z.add_mod(&rd, &curve.n);
            let s_raw = k_inv.mul_mod(&z_plus_rd, &curve.n);
            if s_raw.is_zero() {
                continue;
            }

            let low_s = if s_raw > curve.n_half {
                curve.n.wrapping_sub(&s_raw).0
            } else {
                s_raw
            };
            let high_s = curve.n.wrapping_sub(&low_s).0;
            debug_assert!(low_s <= curve.n_half);
            debug_assert!(high_s > curve.n_half);

            let r_be = r.to_be_bytes_len(clen);
            let low_s_be = low_s.to_be_bytes_len(clen);
            let high_s_be = high_s.to_be_bytes_len(clen);

            let mut low_rs = Vec::with_capacity(2 * clen);
            low_rs.extend_from_slice(&r_be);
            low_rs.extend_from_slice(&low_s_be);

            let high_s_der = encode_der_ecdsa_signature(&r_be, &high_s_be)?;
            return Ok((low_rs, high_s_der));
        }
        Err("failed to find valid ECDSA nonce".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{derive_ecdsa_public_key_uncompressed, sign_ecdsa_with_high_s_der};
    use super::*;

    #[test]
    fn es256_and_es384_high_s_der_normalize_and_verify() {
        for (alg, scalar_len) in [
            (SignatureAlgorithm::Es256, 32usize),
            (SignatureAlgorithm::Es384, 48usize),
        ] {
            let mut d = vec![0x23u8; scalar_len];
            d[0] = 0x07;
            let pubkey = derive_ecdsa_public_key_uncompressed(alg, &d).unwrap();
            let pem = encode_spki_public_key_pem(alg, &pubkey).unwrap();
            let (parsed_alg, parsed_pub, key_id) =
                parse_public_key_material(None, pem.as_bytes(), "spki").unwrap();
            assert_eq!(parsed_alg, alg);
            assert_eq!(parsed_pub, pubkey);
            assert!(key_id.starts_with(&format!("key:{}:sha256:", alg.as_str())));

            let msg = b"DSSEv1 49 application/vnd.r5e.provenance-evidence+json;v=2 2 {}";
            let (expected_low_rs, high_s_der) = sign_ecdsa_with_high_s_der(alg, &d, msg).unwrap();

            // High-S raw r||s must be rejected by strict VERIFY-V2 §2.3 verifier:
            let unnormalized_rs = parse_der_ecdsa_sig_raw(&high_s_der, scalar_len).unwrap();
            assert!(verify_signature(alg, &pubkey, msg, &unnormalized_rs).is_err());

            // Normalizer unwraps DER AND flips S -> n - S to exact low-S r||s:
            let (norm, transformed) =
                normalize_signature_bytes(alg, &high_s_der, Some((&pubkey, msg))).unwrap();
            assert!(transformed);
            assert_eq!(norm, expected_low_rs);
            verify_signature(alg, &pubkey, msg, &norm).expect("normalized low-S verifies");
        }
    }

    #[test]
    fn ed25519_rejects_small_order_and_non_canonical_y() {
        for bad in ED25519_SMALL_ORDER_CLEARED {
            assert!(validate_ed25519_public_key_strict(&bad, "small-order").is_err());
            let mut with_sign = bad;
            with_sign[31] |= 0x80;
            assert!(validate_ed25519_public_key_strict(&with_sign, "small-order-sign").is_err());
        }
        // y = 2^255 - 19 (`edff...7f`) is out of range:
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert!(validate_ed25519_public_key_strict(&p_bytes, "y==p").is_err());
    }
}
