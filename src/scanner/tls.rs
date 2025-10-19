// src/scanner/tls.rs
use anyhow::Result;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use tokio::time::{timeout, Duration};
use std::pin::Pin;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TlsInfo {
    pub alpn: Option<String>,
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub not_after: Option<String>,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub sans: Vec<String>,
}

pub async fn probe_tls(sni_host: &str, ip: &str, port: u16, timeout_secs: u64) -> Result<Option<TlsInfo>> {
    let addr = format!("{}:{}", ip, port);
    let to = Duration::from_secs(timeout_secs);

    let tcp = match timeout(to, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };

    // SslConnector 구성
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);                 // 정보수집 목적(검증 비강제)
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").ok();     // ALPN 요청
    let connector = builder.build();

    // SNI가 들어간 Ssl 객체 생성
    let ssl = connector
        .configure()?
        .use_server_name_indication(true)
        .verify_hostname(false)
        .into_ssl(sni_host)?;

    // TcpStream 을 SslStream 으로 감싸고 비동기 connect 수행
    let mut stream = SslStream::new(ssl, tcp)?;
    let _ = timeout(to, async { Pin::new(&mut stream).connect().await }).await.ok(); // 실패해도 None 반환

    let ssl_ref = stream.ssl();

    // ALPN/버전/암호군
    let alpn    = ssl_ref.selected_alpn_protocol().map(|b| String::from_utf8_lossy(b).to_string());
    let version = Some(ssl_ref.version_str().to_string());   // &str → String
    let cipher  = ssl_ref.current_cipher().map(|c| c.name().to_string());

    // 인증서
    let cert_opt: Option<X509> = ssl_ref.peer_certificate();
    if cert_opt.is_none() {
        return Ok(Some(TlsInfo { alpn, version, cipher, not_after: None, subject_cn: None, issuer_cn: None, sans: vec![] }));
    }
    let cert = cert_opt.unwrap();

    let not_after  = Some(cert.not_after().to_string());
    let subject_cn = cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());
    let issuer_cn  = cert.issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

    let mut sans = Vec::new();
    if let Some(stack) = cert.subject_alt_names() {          // Option 반환
        for gen in stack {
            if let Some(dns) = gen.dnsname() {
                sans.push(dns.to_string());
            }
        }
    }

    Ok(Some(TlsInfo { alpn, version, cipher, not_after, subject_cn, issuer_cn, sans }))
}
