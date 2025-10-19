use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::{timeout, Duration},
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct SshLite {
    pub product: Option<String>,  // 예: "OpenSSH"
    pub version: Option<String>,  // 예: "8.9p1"
    pub raw: String,              // 전체 배너 라인
}

pub async fn probe_ssh(host_ip: &str, port: u16, timeout_secs: u64) -> Result<Option<SshLite>> {
    let addr = format!("{host_ip}:{port}");

    // 접속 타임아웃
    let stream = match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };

    // 서버 식별줄 수신
    let mut rd = BufReader::new(stream);
    let mut line = String::new();
    let n = match timeout(Duration::from_secs(timeout_secs), rd.read_line(&mut line)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    if n == 0 || !line.starts_with("SSH-") {
        return Ok(None);
    }

    // (선택) 우리 식별자 보내기
    let _ = rd.get_mut().write_all(b"SSH-2.0-shadowpaw\r\n").await;

    let raw = line.trim().to_string();

    // 예시 포맷: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    // "SSH-<protover>-<product_ver> ..." 형식을 split
    let mut product: Option<String> = None;
    let mut version: Option<String> = None;

    // "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" -> ["SSH", "2.0", "OpenSSH_8.9p1 Ubuntu-3"]
    let mut parts = raw.splitn(3, '-');
    let _ssh = parts.next();
    let _proto = parts.next();
    if let Some(rest) = parts.next() {
        // rest의 첫 토큰이 "OpenSSH_8.9p1" 같은 형태일 가능성이 큼
        if let Some(first) = rest.split_whitespace().next() {
            if let Some((prod, ver)) = first.split_once('_') {
                product = Some(prod.to_string());
                version = Some(ver.to_string());
            } else {
                product = Some(first.to_string());
            }
        }
    }

    Ok(Some(SshLite { product, version, raw }))
}
