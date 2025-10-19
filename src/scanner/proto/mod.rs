pub mod ssh;

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProtoHit {
    pub name: String,          // "redis" | "mysql" | "postgres" | "rdp" | "smb"
    pub note: Option<String>,  // 버전/특성 등 간단 메모
}

async fn connect(addr: &str, to: Duration) -> Result<TcpStream> {
    Ok(timeout(to, TcpStream::connect(addr)).await??)
}

// Redis: PING → +PONG
pub async fn probe_redis(ip: &str, port: u16, secs: u64) -> Result<Option<ProtoHit>> {
    let to = Duration::from_secs(secs);
    let addr = format!("{ip}:{port}");
    let mut s = match connect(&addr, to).await { Ok(x) => x, _ => return Ok(None) };
    let _ = timeout(to, s.write_all(b"PING\r\n")).await;
    let mut buf = [0u8; 16];
    let n = timeout(to, s.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    if n >= 5 && &buf[..5] == b"+PONG" {
        Ok(Some(ProtoHit{ name: "redis".into(), note: None }))
    } else { Ok(None) }
}

// MySQL: 핸드셰이크 헤더(0x0a) + 버전 문자열
pub async fn probe_mysql(ip: &str, port: u16, secs: u64) -> Result<Option<ProtoHit>> {
    let to = Duration::from_secs(secs);
    let addr = format!("{ip}:{port}");
    let mut s = match connect(&addr, to).await { Ok(x) => x, _ => return Ok(None) };
    let mut buf = [0u8; 128];
    let n = timeout(to, s.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    if n >= 5 && buf[4] == 0x0a {
        let ver = String::from_utf8_lossy(&buf[5..std::cmp::min(n, 64)]).split('\0').next().unwrap_or("").to_string();
        Ok(Some(ProtoHit{ name: "mysql".into(), note: if ver.is_empty(){None}else{Some(ver)} }))
    } else { Ok(None) }
}

// PostgreSQL: SSLRequest → 'S' (지원) / 'N' (미지원)
pub async fn probe_postgres(ip: &str, port: u16, secs: u64) -> Result<Option<ProtoHit>> {
    let to = Duration::from_secs(secs);
    let addr = format!("{ip}:{port}");
    let mut s = match connect(&addr, to).await { Ok(x) => x, _ => return Ok(None) };
    let req: [u8; 8] = [0,0,0,8, 0x04,0xD2,0x16,0x2F]; // SSLRequest
    let _ = timeout(to, s.write_all(&req)).await;
    let mut b = [0u8;1];
    let n = timeout(to, s.read(&mut b)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    if n==1 && (b[0]==b'S' || b[0]==b'N') {
        let note = if b[0]==b'S' { Some("ssl_supported".into()) } else { Some("ssl_not_supported".into()) };
        Ok(Some(ProtoHit{ name: "postgres".into(), note }))
    } else { Ok(None) }
}

// RDP: TPKT(0x03 0x00 …) 응답
pub async fn probe_rdp(ip: &str, port: u16, secs: u64) -> Result<Option<ProtoHit>> {
    let to = Duration::from_secs(secs);
    let addr = format!("{ip}:{port}");
    let mut s = match connect(&addr, to).await { Ok(x) => x, _ => return Ok(None) };
    // 최소 X.224 Connection Request (짧은 템플릿)
    let pkt: [u8; 19] = [0x03,0x00,0x00,0x13, 0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    let _ = timeout(to, s.write_all(&pkt)).await;
    let mut buf = [0u8; 4];
    let n = timeout(to, s.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
    if n==4 && buf[0]==0x03 && buf[1]==0x00 {
        Ok(Some(ProtoHit{ name: "rdp".into(), note: None }))
    } else { Ok(None) }
}

pub async fn probe_smb(ip: &str, port: u16, secs: u64) -> Result<Option<ProtoHit>> {
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::{timeout, Duration}};

    let to   = Duration::from_secs(secs);
    let addr = format!("{ip}:{port}");
    let mut s = match timeout(to, TcpStream::connect(&addr)).await {
        Ok(Ok(x)) => x,
        _ => return Ok(None),
    };


    let smb2_payload: &[u8] = &[
        0xFE, 0x53, 0x4D, 0x42,             // SMB2 magic
        0x40, 0x00, 0x00, 0x00,             // Header flags 등
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x39, 0x00,                         // StructureSize 등
        0x00, 0x00, 0x00, 0x00,             // DialectCount/SecurityMode...
        0x00, 0x00, 0x00, 0x00,             // Reserved/Capabilities
        0x00, 0x00, 0x00, 0x00,             // ClientGuid (dummy)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02,
        0x00, 0x00, 0x00, 0x00,             // padding
        0x00, 0x00, 0x00, 0x00,             // padding
    ];

    // ----- NBSS 헤더(4바이트) + 페이로드 조립 -----
    // NBSS: 1바이트 타입(0x00 = session message) + 3바이트 길이(페이로드 길이)
    let payload_len = smb2_payload.len() as u32; // 24비트에 들어감
    let mut pkt = Vec::<u8>::with_capacity(4 + smb2_payload.len());
    pkt.push(0x00);                                    // Type
    pkt.push(((payload_len >> 16) & 0xFF) as u8);      // Length[23:16]
    pkt.push(((payload_len >> 8)  & 0xFF) as u8);      // Length[15:8]
    pkt.push((payload_len & 0xFF) as u8);              // Length[7:0]
    pkt.extend_from_slice(smb2_payload);

    // 전송
    let _ = timeout(to, s.write_all(&pkt)).await;

    // 아주 짧게 4바이트만 읽어서 NBSS/TPKT류 응답인지 확인
    let mut b = [0u8; 4];
    let n = timeout(to, s.read(&mut b)).await.ok().and_then(|r| r.ok()).unwrap_or(0);

    // NBSS 응답은 보통 b[0]==0x00 (Session message/positive response 등)
    if n >= 4 && b[0] == 0x00 {
        return Ok(Some(ProtoHit { name: "smb".into(), note: None }));
    }
    Ok(None)
}
