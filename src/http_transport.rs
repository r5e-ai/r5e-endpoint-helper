//! Pure-Rust HTTP/1.1 client transport supporting both `http://` and `https://` (`rustls`).
//!
//! Used across all gateway-facing modules (`claim_http`, `enrolment_http`, `evidence_http`,
//! `hold_release`, `root_rotation`) so every command transparently speaks plain HTTP (for
//! loopback / local gateways) and TLS 1.2/1.3 HTTPS with SNI and certificate verification
//! (using `webpki-roots` plus best-effort native OS certificates and an optional custom CA
//! bundle via `R5E_CA_CERT`).

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Optional environment variable pointing to a PEM file with additional trusted CA certificates.
pub const CUSTOM_CA_CERT_ENV_VAR: &str = "R5E_CA_CERT";

/// Opt-in escape hatch allowing bearer tokens over plaintext `http://` to non-loopback hosts.
pub const ALLOW_INSECURE_HTTP_ENV_VAR: &str = "R5E_ALLOW_INSECURE_HTTP";

/// Maximum allowed HTTP response header section size (64 KiB) to guard against OOM.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

/// Maximum allowed HTTP response body size (64 MiB) to guard against OOM.
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Maximum TCP connect timeout per resolved address.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Supported gateway URL schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// Parsed gateway base URL components ready for TCP/TLS connection and HTTP/1.1 framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGatewayUrl {
    pub scheme: HttpScheme,
    /// Hostname or bare IP literal (without IPv6 brackets), used for TLS SNI / server identity.
    pub host: String,
    pub port: u16,
    /// `host:port` (or `[ipv6]:port`) passed to [`TcpStream::connect`].
    pub connect_addr: String,
    /// Value sent in the HTTP/1.1 `Host` header (omits default port if the input omitted it).
    pub host_header: String,
    /// Optional base path prefix without a trailing slash (e.g. `""` or `"/api"`).
    pub base_path: String,
}

/// Parses an `http://` or `https://` gateway base URL.
pub fn parse_gateway_url(raw: &str) -> Result<ParsedGatewayUrl, String> {
    if raw.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(format!(
            "invalid whitespace or control character in gateway URL: {raw:?}"
        ));
    }

    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (HttpScheme::Https, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (HttpScheme::Http, rest)
    } else {
        return Err(format!(
            "expected http:// or https:// gateway URL, got {raw}"
        ));
    };

    let (authority, raw_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    if authority.is_empty() {
        return Err(format!("missing host in gateway URL: {raw}"));
    }
    if authority.contains('@') {
        return Err(format!("userinfo is not supported in gateway URL: {raw}"));
    }
    if authority.contains('?')
        || authority.contains('#')
        || raw_path.contains('?')
        || raw_path.contains('#')
    {
        return Err(format!(
            "query string or fragment is not supported in gateway base URL: {raw}"
        ));
    }

    let (host, port, is_ipv6) = if let Some(after_open) = authority.strip_prefix('[') {
        let close_idx = after_open
            .find(']')
            .ok_or_else(|| format!("unclosed IPv6 literal in gateway URL: {raw}"))?;
        let ipv6_host = &after_open[..close_idx];
        if ipv6_host.is_empty() {
            return Err(format!("missing IPv6 host in gateway URL: {raw}"));
        }
        let remainder = &after_open[close_idx + 1..];
        let port = if remainder.is_empty() {
            scheme.default_port()
        } else if let Some(port_str) = remainder.strip_prefix(':') {
            parse_port(port_str, raw)?
        } else {
            return Err(format!("invalid authority in gateway URL: {raw}"));
        };
        (ipv6_host.to_string(), port, true)
    } else if let Some((h, port_str)) = authority.split_once(':') {
        if h.is_empty() {
            return Err(format!("missing host in gateway URL: {raw}"));
        }
        if port_str.contains(':') {
            return Err(format!("invalid host:port in gateway URL: {raw}"));
        }
        let port = parse_port(port_str, raw)?;
        (h.to_string(), port, false)
    } else {
        (authority.to_string(), scheme.default_port(), false)
    };

    let connect_addr = if is_ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let base_path = raw_path.trim_end_matches('/').to_string();

    Ok(ParsedGatewayUrl {
        scheme,
        host,
        port,
        connect_addr,
        host_header: authority.to_string(),
        base_path,
    })
}

fn parse_port(port_str: &str, raw: &str) -> Result<u16, String> {
    if port_str.is_empty() {
        return Err(format!("empty port in gateway URL: {raw}"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port {port_str:?} in gateway URL: {raw}"))?;
    if port == 0 {
        return Err(format!("port 0 is invalid in gateway URL: {raw}"));
    }
    Ok(port)
}

enum TransportStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

fn build_tls_client_config(extra_ca_pem_path: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Best-effort load of OS trust store so enterprise / corporate CAs work automatically
    // alongside bundled Mozilla roots without failing on minimal container environments.
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    if let Some(path) = extra_ca_pem_path {
        let mut added = 0usize;
        let iter = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("read custom CA PEM {}: {e}", path.display()))?;
        for item in iter {
            let cert = item.map_err(|e| format!("parse custom CA PEM {}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("add custom CA cert from {}: {e}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!(
                "custom CA PEM {} contained no certificates",
                path.display()
            ));
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("configure TLS protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn default_tls_client_config() -> Result<Arc<ClientConfig>, String> {
    if let Some(custom_ca) = std::env::var_os(CUSTOM_CA_CERT_ENV_VAR) {
        if !custom_ca.is_empty() {
            return build_tls_client_config(Some(Path::new(&custom_ca)));
        }
    }

    static CACHED_TLS_CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CACHED_TLS_CONFIG
        .get_or_init(|| build_tls_client_config(None))
        .clone()
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.eq_ignore_ascii_case("localhost.") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn check_bearer_transport_security(
    parsed: &ParsedGatewayUrl,
    has_bearer: bool,
    allow_insecure_http: bool,
) -> Result<(), String> {
    if has_bearer
        && parsed.scheme == HttpScheme::Http
        && !is_loopback_host(&parsed.host)
        && !allow_insecure_http
    {
        return Err(format!(
            "refusing to send bearer token over plaintext http:// to non-loopback host {:?}; use https:// or set {ALLOW_INSECURE_HTTP_ENV_VAR}=1 to override",
            parsed.host
        ));
    }
    Ok(())
}

fn validate_request_path(path: &str) -> Result<(), String> {
    if path
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(format!(
            "invalid whitespace or control character in request path: {path:?}"
        ));
    }
    Ok(())
}

fn connect_tcp_with_timeout(connect_addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let connect_timeout = if timeout.is_zero() {
        DEFAULT_CONNECT_TIMEOUT
    } else {
        timeout.min(DEFAULT_CONNECT_TIMEOUT)
    };
    let addrs: Vec<_> = connect_addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {connect_addr}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {connect_addr}: no addresses returned"));
    }
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(format!(
        "connect {connect_addr}: {}",
        last_err.expect("non-empty addrs yields at least one error")
    ))
}

/// Executes a single HTTP/1.1 request over plain TCP (`http://`) or TLS (`https://`).
pub fn send_http11_request(
    gateway_base_url: &str,
    timeout: Duration,
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    json_body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let parsed = parse_gateway_url(gateway_base_url)?;
    validate_request_path(path)?;
    let full_path = format!("{}{path}", parsed.base_path);
    validate_request_path(&full_path)?;

    let allow_insecure_http = std::env::var(ALLOW_INSECURE_HTTP_ENV_VAR).is_ok_and(|v| v == "1");
    check_bearer_transport_security(&parsed, bearer_token.is_some(), allow_insecure_http)?;

    let tcp = connect_tcp_with_timeout(&parsed.connect_addr, timeout)?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut stream = match parsed.scheme {
        HttpScheme::Http => TransportStream::Plain(tcp),
        HttpScheme::Https => {
            let tls_cfg = default_tls_client_config()?;
            let server_name = ServerName::try_from(parsed.host.clone())
                .map_err(|e| format!("invalid TLS server name {:?}: {e}", parsed.host))?;
            let conn = ClientConnection::new(tls_cfg, server_name)
                .map_err(|e| format!("init TLS connection to {}: {e}", parsed.host))?;
            TransportStream::Tls(Box::new(StreamOwned::new(conn, tcp)))
        }
    };

    let mut req_head = format!(
        "{method} {full_path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: r5e-endpoint-helper/{}\r\nAccept: application/json\r\nConnection: close\r\n",
        parsed.host_header,
        env!("CARGO_PKG_VERSION"),
    );
    if let Some(token) = bearer_token {
        if token.contains('\r') || token.contains('\n') {
            return Err("bearer token contains illegal CR/LF characters".to_string());
        }
        req_head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = json_body {
        req_head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req_head.push_str("\r\n");

    stream
        .write_all(req_head.as_bytes())
        .and_then(|_| {
            if let Some(body) = json_body {
                stream.write_all(body)
            } else {
                Ok(())
            }
        })
        .and_then(|_| stream.flush())
        .map_err(|e| format!("write {method} {full_path}: {e}"))?;

    let mut reader = BufReader::new(stream);
    read_http11_response(
        &mut reader,
        MAX_RESPONSE_HEADER_BYTES,
        MAX_RESPONSE_BODY_BYTES,
    )
}

fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    context: &str,
) -> Result<String, String> {
    let mut line = String::new();
    let limit = max_bytes.saturating_add(1) as u64;
    let n = reader
        .take(limit)
        .read_line(&mut line)
        .map_err(|e| format!("{context}: {e}"))?;
    if n > max_bytes {
        return Err(format!(
            "{context}: line exceeds maximum allowed size ({max_bytes} bytes)"
        ));
    }
    Ok(line)
}

fn read_http11_response<R: BufRead>(
    reader: &mut R,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<(u16, Vec<u8>), String> {
    let mut header_bytes_read = 0usize;

    let status_line = read_line_bounded(reader, max_header_bytes, "read status line")?;
    header_bytes_read = header_bytes_read.saturating_add(status_line.len());
    if header_bytes_read > max_header_bytes {
        return Err(format!(
            "response headers exceed maximum allowed size ({max_header_bytes} bytes)"
        ));
    }

    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed HTTP status line: {status_line:?}"))?
        .parse()
        .map_err(|e| format!("invalid HTTP status: {e}"))?;

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    loop {
        let remaining = max_header_bytes.saturating_sub(header_bytes_read);
        let line = read_line_bounded(reader, remaining, "read header")?;
        if line.is_empty() {
            return Err("unexpected EOF while reading response headers".to_string());
        }
        header_bytes_read = header_bytes_read.saturating_add(line.len());
        if header_bytes_read > max_header_bytes {
            return Err(format!(
                "response headers exceed maximum allowed size ({max_header_bytes} bytes)"
            ));
        }
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
        read_chunked_body_bounded(reader, max_header_bytes, max_body_bytes)?
    } else if let Some(len) = content_length {
        if len > max_body_bytes {
            return Err(format!(
                "response Content-Length ({len} bytes) exceeds maximum allowed size ({max_body_bytes} bytes)"
            ));
        }
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("read body ({len}B): {e}"))?;
        buf
    } else {
        let mut buf = Vec::new();
        let limit = max_body_bytes.saturating_add(1) as u64;
        reader
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| format!("read body EOF: {e}"))?;
        if buf.len() > max_body_bytes {
            return Err(format!(
                "response body exceeds maximum allowed size ({max_body_bytes} bytes)"
            ));
        }
        buf
    };

    Ok((status, body))
}

/// Reads an HTTP/1.1 `Transfer-Encoding: chunked` body to completion within bounded header/body caps.
fn read_chunked_body_bounded<R: BufRead>(
    reader: &mut R,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let size_line = read_line_bounded(reader, max_header_bytes, "read chunk size")?;
        let hex_part = size_line
            .trim()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|e| format!("invalid chunk size {hex_part:?}: {e}"))?;
        if chunk_len == 0 {
            let mut trailer_bytes = 0usize;
            loop {
                let remaining = max_header_bytes.saturating_sub(trailer_bytes);
                let trailer = read_line_bounded(reader, remaining, "read chunk trailer")?;
                if trailer.is_empty() {
                    break;
                }
                trailer_bytes = trailer_bytes.saturating_add(trailer.len());
                if trailer_bytes > max_header_bytes {
                    return Err(format!(
                        "chunked trailers exceed maximum allowed size ({max_header_bytes} bytes)"
                    ));
                }
                if trailer.trim_end_matches(&['\r', '\n'][..]).is_empty() {
                    break;
                }
            }
            break;
        }
        let next_len = out.len().checked_add(chunk_len);
        if next_len.is_none_or(|n| n > max_body_bytes) {
            return Err(format!(
                "chunked response body exceeds maximum allowed size ({max_body_bytes} bytes)"
            ));
        }
        let mut chunk = vec![0u8; chunk_len];
        reader
            .read_exact(&mut chunk)
            .map_err(|e| format!("read chunk data: {e}"))?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|e| format!("read chunk CRLF: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_default_port_80() {
        let parsed = parse_gateway_url("http://example.com").expect("parse http default port");
        assert_eq!(parsed.scheme, HttpScheme::Http);
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.connect_addr, "example.com:80");
        assert_eq!(parsed.host_header, "example.com");
        assert_eq!(parsed.base_path, "");
    }

    #[test]
    fn parse_https_default_port_443() {
        let parsed = parse_gateway_url("https://dev.r5e.io").expect("parse https default port");
        assert_eq!(parsed.scheme, HttpScheme::Https);
        assert_eq!(parsed.host, "dev.r5e.io");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.connect_addr, "dev.r5e.io:443");
        assert_eq!(parsed.host_header, "dev.r5e.io");
        assert_eq!(parsed.base_path, "");
    }

    #[test]
    fn parse_https_trailing_slash_and_base_path() {
        let parsed =
            parse_gateway_url("https://api.r5e.io/gateway/").expect("parse https base path");
        assert_eq!(parsed.scheme, HttpScheme::Https);
        assert_eq!(parsed.host, "api.r5e.io");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.connect_addr, "api.r5e.io:443");
        assert_eq!(parsed.host_header, "api.r5e.io");
        assert_eq!(parsed.base_path, "/gateway");
    }

    #[test]
    fn parse_explicit_ports_for_http_and_https() {
        let http = parse_gateway_url("http://127.0.0.1:4000/v0").expect("parse http explicit port");
        assert_eq!(http.scheme, HttpScheme::Http);
        assert_eq!(http.host, "127.0.0.1");
        assert_eq!(http.port, 4000);
        assert_eq!(http.connect_addr, "127.0.0.1:4000");
        assert_eq!(http.host_header, "127.0.0.1:4000");
        assert_eq!(http.base_path, "/v0");

        let https =
            parse_gateway_url("https://dev.r5e.io:8443/prefix").expect("parse https explicit port");
        assert_eq!(https.scheme, HttpScheme::Https);
        assert_eq!(https.host, "dev.r5e.io");
        assert_eq!(https.port, 8443);
        assert_eq!(https.connect_addr, "dev.r5e.io:8443");
        assert_eq!(https.host_header, "dev.r5e.io:8443");
        assert_eq!(https.base_path, "/prefix");
    }

    #[test]
    fn parse_ipv6_literals() {
        let bare = parse_gateway_url("https://[::1]").expect("parse ipv6 default port");
        assert_eq!(bare.scheme, HttpScheme::Https);
        assert_eq!(bare.host, "::1");
        assert_eq!(bare.port, 443);
        assert_eq!(bare.connect_addr, "[::1]:443");
        assert_eq!(bare.host_header, "[::1]");
        assert_eq!(bare.base_path, "");

        let explicit = parse_gateway_url("http://[::1]:4000/api").expect("parse ipv6 explicit");
        assert_eq!(explicit.scheme, HttpScheme::Http);
        assert_eq!(explicit.host, "::1");
        assert_eq!(explicit.port, 4000);
        assert_eq!(explicit.connect_addr, "[::1]:4000");
        assert_eq!(explicit.host_header, "[::1]:4000");
        assert_eq!(explicit.base_path, "/api");
    }

    #[test]
    fn reject_unsupported_schemes_and_malformed_urls() {
        for bad in [
            "ftp://dev.r5e.io",
            "ws://dev.r5e.io",
            "wss://dev.r5e.io",
            "file:///tmp/gateway",
            "dev.r5e.io",
            "http://",
            "https://",
            "https:///v1/deployment",
            "https://:443",
            "https://dev.r5e.io:",
            "https://dev.r5e.io:0",
            "https://dev.r5e.io:abc",
            "https://dev.r5e.io:70000",
            "https://user:pass@dev.r5e.io",
            "https://dev.r5e.io?foo=bar",
            "https://dev.r5e.io/path\r\nX-Injected: 1",
            "https://[::1",
        ] {
            assert!(
                parse_gateway_url(bad).is_err(),
                "expected URL {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn default_tls_config_builds_with_roots() {
        let cfg = build_tls_client_config(None).expect("build default rustls config");
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn custom_ca_missing_file_returns_clear_error() {
        let err = build_tls_client_config(Some(Path::new("/nonexistent/r5e-test-ca.pem")))
            .expect_err("missing custom CA file must fail");
        assert!(
            err.contains("read custom CA PEM"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn s1_rejects_oversized_content_length_before_allocating() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n";
        let mut cursor = io::Cursor::new(&raw[..]);
        let err = read_http11_response(&mut cursor, 4096, 1024)
            .expect_err("huge Content-Length must be rejected before allocation");
        assert!(
            err.contains("exceeds maximum allowed size"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn s1_rejects_oversized_chunked_and_close_delimited_bodies() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n";
        let mut cursor = io::Cursor::new(&chunked[..]);
        let err = read_http11_response(&mut cursor, 4096, 8)
            .expect_err("oversized chunked body must be rejected");
        assert!(
            err.contains("chunked response body exceeds maximum allowed size"),
            "unexpected error: {err}"
        );

        let eof_body = b"HTTP/1.1 200 OK\r\n\r\n0123456789";
        let mut cursor = io::Cursor::new(&eof_body[..]);
        let err = read_http11_response(&mut cursor, 4096, 8)
            .expect_err("oversized close-delimited body must be rejected");
        assert!(
            err.contains("response body exceeds maximum allowed size"),
            "unexpected error: {err}"
        );

        let ok_eof = b"HTTP/1.1 200 OK\r\n\r\n01234567";
        let mut cursor = io::Cursor::new(&ok_eof[..]);
        let (status, body) =
            read_http11_response(&mut cursor, 4096, 8).expect("body at exact cap must succeed");
        assert_eq!(status, 200);
        assert_eq!(body, b"01234567");
    }

    #[test]
    fn s1_rejects_oversized_header_section() {
        let mut resp = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..20 {
            resp.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "a".repeat(32)).as_bytes());
        }
        resp.extend_from_slice(b"\r\n");
        let mut cursor = io::Cursor::new(&resp[..]);
        let err = read_http11_response(&mut cursor, 128, 1024)
            .expect_err("oversized header section must be rejected");
        assert!(
            err.contains("exceeds maximum allowed size")
                || err.contains("exceed maximum allowed size"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn s2_refuses_bearer_over_plaintext_http_to_non_loopback_unless_overridden() {
        for remote in [
            "http://dev.r5e.io",
            "http://10.0.0.5:4000",
            "http://[2001:db8::1]:4000",
        ] {
            let parsed = parse_gateway_url(remote).unwrap();
            let err = check_bearer_transport_security(&parsed, true, false)
                .expect_err("bearer over plaintext http to remote host must fail");
            assert!(
                err.contains(ALLOW_INSECURE_HTTP_ENV_VAR),
                "expected override hint in error: {err}"
            );
            check_bearer_transport_security(&parsed, true, true)
                .expect("explicit R5E_ALLOW_INSECURE_HTTP=1 override must permit");
            check_bearer_transport_security(&parsed, false, false)
                .expect("unauthenticated http GET to remote host stays allowed");
        }

        for allowed in [
            "http://127.0.0.1:4000",
            "http://127.0.1.1:4000",
            "http://localhost:4000",
            "http://LOCALHOST:4000",
            "http://[::1]:4000",
            "https://dev.r5e.io",
            "https://10.0.0.5:8443",
        ] {
            let parsed = parse_gateway_url(allowed).unwrap();
            check_bearer_transport_security(&parsed, true, false)
                .unwrap_or_else(|e| panic!("expected {allowed} to allow bearer token: {e}"));
        }
    }

    #[test]
    fn n2_rejects_control_and_whitespace_bytes_in_request_path() {
        for bad in [
            "/v1/deployment HTTP/1.1\r\nHost: evil",
            "/v1/foo\r\nX-Injected: 1",
            "/v1/foo\nbar",
            "/v1/foo bar",
            "/v1/foo\tbar",
            "/v1/foo\0bar",
            "/v1/foo\x7fbar",
        ] {
            assert!(
                validate_request_path(bad).is_err(),
                "expected path {bad:?} to be rejected"
            );
        }

        for ok in [
            "/v1/deployment",
            "/v1/evidence/records",
            "/v1/items?limit=10",
        ] {
            validate_request_path(ok)
                .unwrap_or_else(|e| panic!("expected path {ok:?} to be accepted: {e}"));
        }
    }
}
