// src/scanner/http.rs
use anyhow::Result;
use regex::Regex;
use reqwest::{Client, StatusCode};
use std::time::Duration;

#[derive(Debug)]
pub struct HttpInfo {
    pub service: Option<String>, // from Server header (owned)
    pub title: Option<String>,   // <title> if found
    pub robots: Option<RobotsInfo>,
}

#[derive(Debug)]
pub struct RobotsInfo {
    pub exists: bool,
    pub status: u16,
    pub body_snippet: Option<String>,
}

pub async fn probe_http(host: &str, port: u16, timeout_secs: u64) -> Result<HttpInfo> {
    let scheme = if port == 443 { "https" } else { "http" };
    // if host already contains scheme/port style, it will still work; we format host:port explicitly
    let base = format!("{scheme}://{host}:{port}");

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("web_scanner/0.1")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    // main path probe
    let mut service_header: Option<String> = None;
    let mut title: Option<String> = None;
    let mut robots: Option<RobotsInfo> = None;

    if let Ok(resp) = client.get(&base).send().await {
        // server header
        if let Some(h) = resp.headers().get(reqwest::header::SERVER) {
            if let Ok(s) = h.to_str() {
                service_header = Some(s.to_string());
            }
        }

        // try to read body (may fail for non-html or streaming responses)
        if let Ok(body) = resp.text().await {
            // extract title (case-insensitive, dotall)
            if title.is_none() {
                if let Ok(re) = Regex::new("(?is)<title[^>]*>(.*?)</title>") {
                    if let Some(cap) = re.captures(&body) {
                        if let Some(m) = cap.get(1) {
                            title = Some(m.as_str().trim().to_string());
                        }
                    }
                }
            }
            // not saving full body; if needed we could store snippet
            // nothing else here
        }
    }

    // robots.txt probe (quick, small)
    let robots_url = format!("{}/robots.txt", base);
    match client.get(&robots_url).send().await {
        Ok(r) => {
            let status = r.status();
            let exists = status.is_success();
            let mut snippet = None;
            if exists {
                if let Ok(body) = r.text().await {
                    // keep only first 512 chars to avoid large storage
                    let s = body.trim();
                    snippet = Some(s.chars().take(512).collect());
                }
            }
            robots = Some(RobotsInfo {
                exists,
                status: status.as_u16(),
                body_snippet: snippet,
            });
        }
        Err(_) => {
            robots = Some(RobotsInfo {
                exists: false,
                status: 0,
                body_snippet: None,
            });
        }
    }

    Ok(HttpInfo {
        service: service_header,
        title,
        robots,
    })
}
