use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::collections::BTreeSet;

pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut set = BTreeSet::new(); // 정렬 + 중복 제거
    for raw in spec.split(',') {
        let part = raw.trim();
        if part.is_empty() { continue; }

        if let Some((a, b)) = part.split_once('-') {
            let start: u32 = a.trim().parse().map_err(|_| format!("invalid number: {}", a))?;
            let end:   u32 = b.trim().parse().map_err(|_| format!("invalid number: {}", b))?;
            if start == 0 || end == 0 || start > 65535 || end > 65535 || start > end {
                return Err(format!("invalid range: {}", part));
            }
            for p in start..=end {
                set.insert(p as u16);
            } 
        } else {
            let p: u32 = part.parse().map_err(|_| format!("invalid number: {}", part))?;
            if p == 0 || p > 65535 {
                return Err(format!("invalid port: {}", part));
            }
            set.insert(p as u16);
        }
    }
    Ok(set.into_iter().collect())
}

pub async fn scan_port(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,
        _ => false,
    }
}

