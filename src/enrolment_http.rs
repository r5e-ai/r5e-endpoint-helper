//! Zero-dependency HTTP/1.1 client for `r5e-endpoint-helper` Badge enrolment against `recurse_gateway`:
//! - `POST /v1/authority/badges/prepare`
//! - `POST /v1/authority/badges/finalize`
//!
//! Handles both `Content-Length` and `Transfer-Encoding: chunked` responses (Bandit / Cowboy),
//! enforces pre-signing draft verification (`counter_sign_prepared_badge`), and returns an
//! `EnrolledEndpointSession` ready for offline supervision and bundle export.

use crate::attestation::{
    counter_sign_prepared_badge, EnrolledEndpointSession, EnrolledSessionOptions,
    FinalizeBadgeRequest, FinalizedBadgeResponse, PrepareBadgeRequest, PreparedBadgeResponse,
    SubjectPublicKey,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const PREPARE_BADGE_PATH: &str = "/v1/authority/badges/prepare";
pub const FINALIZE_BADGE_PATH: &str = "/v1/authority/badges/finalize";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEnrolmentError {
    /// `409 {"error": "gateway_has_no_endorsement"}`
    GatewayHasNoEndorsement(String),
    /// `403` policy denial
    PolicyForbidden(String),
    /// `422` bad key, expired/mismatched ticket, or bad signature
    Unprocessable {
        error_code: Option<String>,
        body: String,
    },
    /// Unexpected HTTP status
    HttpStatus { status: u16, body: String },
    /// Local pre-signing or post-finalization cryptographic / bounds refusal
    Validation(String),
    /// Socket / framing / JSON parse failure
    Transport(String),
}

impl std::fmt::Display for GatewayEnrolmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GatewayHasNoEndorsement(b) => write!(f, "gateway has no endorsement (409): {b}"),
            Self::PolicyForbidden(b) => write!(f, "enrolment denied by policy (403): {b}"),
            Self::Unprocessable { error_code, body } => {
                write!(f, "unprocessable enrolment (422 {:?}): {body}", error_code)
            }
            Self::HttpStatus { status, body } => write!(f, "HTTP {status}: {body}"),
            Self::Validation(msg) => write!(f, "enrolment validation failed: {msg}"),
            Self::Transport(msg) => write!(f, "enrolment transport error: {msg}"),
        }
    }
}

impl std::error::Error for GatewayEnrolmentError {}

#[derive(Clone)]
pub struct EnrolmentClientConfig {
    /// Base HTTP URL such as `"http://127.0.0.1:4000"` (optional path prefix supported).
    pub gateway_base_url: String,
    /// Optional `Authorization: Bearer <token>` value (redacted in `Debug`).
    pub bearer_token: Option<String>,
    pub timeout: Duration,
}

impl std::fmt::Debug for EnrolmentClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolmentClientConfig")
            .field("gateway_base_url", &self.gateway_base_url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl EnrolmentClientConfig {
    pub fn new(gateway_base_url: impl Into<String>, bearer_token: Option<String>) -> Self {
        Self {
            gateway_base_url: gateway_base_url.into(),
            bearer_token,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Extended options for [`enrol_endpoint_badge_with_options`].
#[derive(Debug, Clone, Default)]
pub struct EnrolBadgeOptions {
    /// Optional human-readable purpose sent on `POST /v1/authority/badges/prepare`.
    pub purpose: Option<String>,
    /// Local `CaptureProfile` options (including optional `retention_override` and `policy_required_kinds`).
    pub session_options: EnrolledSessionOptions,
}

/// Executes the full 2-step stateless `prepare` -> `finalize` `Badge` enrolment against a running
/// `recurse_gateway` and returns an `EnrolledEndpointSession`.
#[allow(clippy::too_many_arguments)]
pub fn enrol_endpoint_badge(
    cfg: &EnrolmentClientConfig,
    helper_key: SigningKey,
    holder: &str,
    workload: Option<String>,
    requested_kinds: Vec<String>,
    requested_actor_prefixes: Option<Vec<String>>,
    requested_ttl_seconds: Option<u64>,
    cedar_policy_bytes: &[u8],
) -> Result<EnrolledEndpointSession, GatewayEnrolmentError> {
    let (session, _finalized) = enrol_endpoint_badge_with_options(
        cfg,
        helper_key,
        holder,
        workload,
        requested_kinds,
        requested_actor_prefixes,
        requested_ttl_seconds,
        cedar_policy_bytes,
        &EnrolBadgeOptions::default(),
    )?;
    Ok(session)
}

/// Executes the 2-step `Badge` enrolment with optional `purpose` and [`EnrolledSessionOptions`],
/// returning both the [`EnrolledEndpointSession`] and the raw [`FinalizedBadgeResponse`].
#[allow(clippy::too_many_arguments)]
pub fn enrol_endpoint_badge_with_options(
    cfg: &EnrolmentClientConfig,
    helper_key: SigningKey,
    holder: &str,
    workload: Option<String>,
    requested_kinds: Vec<String>,
    requested_actor_prefixes: Option<Vec<String>>,
    requested_ttl_seconds: Option<u64>,
    cedar_policy_bytes: &[u8],
    options: &EnrolBadgeOptions,
) -> Result<(EnrolledEndpointSession, FinalizedBadgeResponse), GatewayEnrolmentError> {
    if let Some(ref tok) = cfg.bearer_token {
        if tok.contains('\r') || tok.contains('\n') {
            return Err(GatewayEnrolmentError::Validation(
                "bearer token contains illegal CR/LF characters".to_string(),
            ));
        }
    }

    let pub_b64 = BASE64_STANDARD.encode(helper_key.verifying_key().to_bytes());
    let prepare_req = PrepareBadgeRequest {
        subject_key: SubjectPublicKey {
            algorithm: "ed25519".to_string(),
            bytes: pub_b64,
        },
        holder: holder.to_string(),
        workload,
        requested_kinds,
        requested_actor_prefixes: requested_actor_prefixes.clone(),
        requested_ttl_seconds,
    };

    let mut prepare_val = serde_json::to_value(&prepare_req)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("serialize prepare: {e}")))?;
    if let Some(ref purpose) = options.purpose {
        if let Some(obj) = prepare_val.as_object_mut() {
            obj.insert("purpose".to_string(), Value::String(purpose.clone()));
        }
    }
    let prepare_body = serde_json::to_vec(&prepare_val)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("serialize prepare bytes: {e}")))?;
    let (prep_status, prep_resp_bytes) = post_json_http11(cfg, PREPARE_BADGE_PATH, &prepare_body)?;
    if prep_status != 200 {
        return Err(classify_error_status(prep_status, &prep_resp_bytes));
    }

    let prepared: PreparedBadgeResponse = serde_json::from_slice(&prep_resp_bytes)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("parse prepare 200 JSON: {e}")))?;

    let finalize_req: FinalizeBadgeRequest =
        counter_sign_prepared_badge(&helper_key, &prepare_req, &prepared)
            .map_err(GatewayEnrolmentError::Validation)?;

    let finalize_body = serde_json::to_vec(&finalize_req)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("serialize finalize: {e}")))?;
    let (fin_status, fin_resp_bytes) = post_json_http11(cfg, FINALIZE_BADGE_PATH, &finalize_body)?;
    if fin_status != 201 && fin_status != 200 {
        return Err(classify_error_status(fin_status, &fin_resp_bytes));
    }

    let finalized: FinalizedBadgeResponse = serde_json::from_slice(&fin_resp_bytes)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("parse finalize 201 JSON: {e}")))?;

    let actor_prefixes = requested_actor_prefixes.unwrap_or_else(|| vec!["urn:r5e:".to_string()]);
    let session = EnrolledEndpointSession::from_finalized_with_options(
        helper_key,
        &finalize_req,
        &finalized,
        cedar_policy_bytes,
        &actor_prefixes,
        &options.session_options,
    )
    .map_err(GatewayEnrolmentError::Validation)?;
    Ok((session, finalized))
}

fn classify_error_status(status: u16, body_bytes: &[u8]) -> GatewayEnrolmentError {
    let body_text = String::from_utf8_lossy(body_bytes).into_owned();
    let error_code = serde_json::from_slice::<Value>(body_bytes)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    match status {
        409 => GatewayEnrolmentError::GatewayHasNoEndorsement(body_text),
        403 => GatewayEnrolmentError::PolicyForbidden(body_text),
        422 => GatewayEnrolmentError::Unprocessable {
            error_code,
            body: body_text,
        },
        other => GatewayEnrolmentError::HttpStatus {
            status: other,
            body: body_text,
        },
    }
}

fn parse_http_base_url(raw: &str) -> Result<(String, String), GatewayEnrolmentError> {
    let rest = raw.strip_prefix("http://").ok_or_else(|| {
        GatewayEnrolmentError::Transport(format!("expected http:// gateway URL, got {raw}"))
    })?;
    let (host_port, base_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let connect_addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    Ok((connect_addr, base_path.to_string()))
}

fn post_json_http11(
    cfg: &EnrolmentClientConfig,
    path: &str,
    json_body: &[u8],
) -> Result<(u16, Vec<u8>), GatewayEnrolmentError> {
    let (connect_addr, base_path) = parse_http_base_url(&cfg.gateway_base_url)?;
    let full_path = format!("{base_path}{path}");

    let mut stream = TcpStream::connect(&connect_addr)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("connect {connect_addr}: {e}")))?;
    let _ = stream.set_read_timeout(Some(cfg.timeout));
    let _ = stream.set_write_timeout(Some(cfg.timeout));

    let mut req_head = format!(
        "POST {full_path} HTTP/1.1\r\nHost: {connect_addr}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        json_body.len()
    );
    if let Some(ref bearer) = cfg.bearer_token {
        req_head.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
    }
    req_head.push_str("\r\n");

    stream
        .write_all(req_head.as_bytes())
        .and_then(|_| stream.write_all(json_body))
        .and_then(|_| stream.flush())
        .map_err(|e| GatewayEnrolmentError::Transport(format!("write request: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| GatewayEnrolmentError::Transport(format!("read status line: {e}")))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            GatewayEnrolmentError::Transport(format!("malformed HTTP status line: {status_line:?}"))
        })?
        .parse()
        .map_err(|e| GatewayEnrolmentError::Transport(format!("invalid HTTP status: {e}")))?;

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read header: {e}")))?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            let name_lc = name.trim().to_ascii_lowercase();
            let val_trim = val.trim();
            if name_lc == "content-length" {
                content_length = val_trim.parse::<usize>().ok();
            } else if name_lc == "transfer-encoding"
                && val_trim.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read body ({len}B): {e}")))?;
        buf
    } else {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read body EOF: {e}")))?;
        buf
    };

    Ok((status, body))
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, GatewayEnrolmentError> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        reader
            .read_line(&mut size_line)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read chunk size: {e}")))?;
        let hex_part = size_line
            .trim()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let chunk_len = usize::from_str_radix(hex_part, 16).map_err(|e| {
            GatewayEnrolmentError::Transport(format!("invalid chunk size {hex_part:?}: {e}"))
        })?;
        if chunk_len == 0 {
            let mut crlf = String::new();
            let _ = reader.read_line(&mut crlf);
            break;
        }
        let mut chunk = vec![0u8; chunk_len];
        reader
            .read_exact(&mut chunk)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read chunk data: {e}")))?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|e| GatewayEnrolmentError::Transport(format!("read chunk CRLF: {e}")))?;
    }
    Ok(out)
}
