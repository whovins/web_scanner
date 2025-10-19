use anyhow::Result;
use sha1::{Digest, Sha1};
use std::time::Duration;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::timeout};

#[derive(Debug, Clone)]
pub struct BannerInfo {
    pub banner: String,              // UTF-8 lossy
    pub banner_sha1: String,         // hex
    pub service_guess: Option<String>,
}

pub async fn grab_banner(host: &str, port: u16, timeout_secs: u64) -> Result<Option<BannerInfo>> {
    let addr = format!("{}:{}", host, port);
    let to = Duration::from_secs(timeout_secs);

    // 접속 시도
    let mut s = match timeout(to, TcpStream::connect(&addr)).await {
        Ok(Ok(sock)) => sock,
        _ => return Ok(None),
    };

    // 포트별 가벼운 프로브 전략
    let mut buf = vec![0u8; 1024];

    let banner = match port {
        22 => { // SSH: 서버가 먼저 “SSH-2.0-…” 라인 보냄
            let n = read_some(&mut s, &mut buf, to, 600).await?;
            String::from_utf8_lossy(&buf[..n]).to_string()
        }
        21 => { // FTP: 220 배너
            let n = read_some(&mut s, &mut buf, to, 600).await?;
            String::from_utf8_lossy(&buf[..n]).to_string()
        }
        25 | 587 | 2525 => { // SMTP: 배너 수신 후 EHLO 1회
            let _ = read_some(&mut s, &mut buf, to, 600).await?;
            let _ = timeout(to, s.write_all(b"EHLO scanx.local\r\n")).await;
            let n = read_some(&mut s, &mut buf, to, 600).await.unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).to_string()
        }
        _ => {
            // 제너릭: 먼저 읽기(배너 선송신 서비스), 없으면 짧게 빈 write 후 다시 읽기
            let n1 = read_some(&mut s, &mut buf, to, 300).await.unwrap_or(0);
            if n1 > 0 {
                String::from_utf8_lossy(&buf[..n1]).to_string()
            } else {
                let _ = timeout(to, s.write_all(b"\r\n")).await;
                let n2 = read_some(&mut s, &mut buf, to, 300).await.unwrap_or(0);
                String::from_utf8_lossy(&buf[..n2]).to_string()
            }
        }
    };

    let banner_trim = banner.trim().to_string();
    if banner_trim.is_empty() {
        return Ok(None);
    }

    let mut hasher = Sha1::new();
    hasher.update(banner_trim.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    let guess = guess_service_from_banner(port, &banner_trim);

    Ok(Some(BannerInfo {
        banner: banner_trim,
        banner_sha1: hash,
        service_guess: guess,
    }))
}

async fn read_some(s: &mut TcpStream, buf: &mut [u8], to: Duration, per_read_ms: u64) -> Result<usize> {
    match timeout(to.min(Duration::from_millis(per_read_ms)), s.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        _ => Ok(0),
    }
}

fn guess_service_from_banner(port: u16, b: &str) -> Option<String> {
    let bl = b.to_ascii_lowercase();
    if bl.contains("ssh-") || port == 22 {
        return Some("ssh".into());
    }
    if bl.contains("smtp") || bl.starts_with("220 ") || port == 25 || port == 587 || port == 2525 {
        return Some("smtp".into());
    }
    if bl.contains("ftp") || port == 21 {
        return Some("ftp".into());
    }
    if bl.contains("redis") { return Some("redis".into()); }
    if bl.contains("postgresql") || bl.contains("postgres") { return Some("postgres".into()); }
    if bl.contains("mysql") { return Some("mysql".into()); }
    if bl.contains("mongodb") { return Some("mongodb".into()); }
    None
}
