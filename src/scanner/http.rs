// src/scanner/http.rs
use anyhow::Result;
use regex::Regex;
use reqwest::{Client, StatusCode};
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathCheck {
    pub path: String,
    pub status: u16,
    pub exists: bool,
    pub snippet: Option<String>,
    pub hints: Vec<String>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Warning {
    pub level: String,       // "info" | "warning" | "critical"
    pub message: String,
    pub confidence: f32,     // 0.0 ~ 1.0
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpInfo {
    pub service: Option<String>, // from Server header (owned)
    pub title: Option<String>,   // <title> if found
    pub robots: Option<RobotsInfo>,
    pub warnings: Vec<Warning>,  // structured warnings
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RobotsInfo {
    pub exists: bool,
    pub status: u16,
    pub body_snippet: Option<String>,
}

fn analyze_snippet(snippet: &str) -> Vec<String> {
    let s = snippet.to_lowercase();
    let mut hints = Vec::new();
    if s.contains("<form") {
        hints.push("login_form".to_string());
    }
    if s.contains("type=\"password\"") || s.contains("input password") {
        hints.push("password_field".to_string());
    }
    if s.contains("index of /") || s.contains("<title>index of") {
        hints.push("directory_listing".to_string());
    }
    if s.contains(".git") || s.contains("git/") || s.contains("ref: refs/heads") {
        hints.push("git_exposed".to_string());
    }
    if s.contains("wp-login.php") || s.contains("wordpress") {
        hints.push("wp_login".to_string());
    }
    if s.contains("admin") && (s.contains("/admin") || s.contains("administrator") || s.contains("관리자")) {
        hints.push("admin_page".to_string());
    }
    hints
}

fn add_warning(warnings: &mut Vec<Warning>, level: &str, msg: impl Into<String>, confidence: f32) {
    warnings.push(Warning {
        level: level.to_string(),
        message: msg.into(),
        confidence,
    });
}

fn parse_set_cookie_flags(set_cookie_vals: &Vec<String>, warnings: &mut Vec<Warning>) {
    for raw in set_cookie_vals.iter() {
        // cookie 형식의 앞부분에서 이름=값 추출
        let parts: Vec<&str> = raw.split(';').map(|s| s.trim()).collect();
        if parts.is_empty() { continue; }
        let name_val = parts[0];
        let mut has_secure = false;
        let mut has_httponly = false;
        for p in parts.iter().skip(1) {
            let lower = p.to_lowercase();
            if lower == "secure" { has_secure = true; }
            if lower == "httponly" { has_httponly = true; }
        }
        if !has_secure || !has_httponly {
            let mut msg = format!("Set-Cookie for '{}' missing flags:", name_val);
            if !has_secure { msg.push_str(" Secure"); }
            if !has_httponly { msg.push_str(" HttpOnly"); }
            add_warning(warnings, "warning", msg, 0.7);
        }
    }
}



pub async fn probe_paths(host: &str, port: u16, timeout_secs: u64, paths: &[String]) -> Result<Vec<PathCheck>> {
    let scheme = if port == 443 { "https" } else { "http" };
    let base = format!("{scheme}://{host}:{port}");

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("web_scanner/0.1")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut out: Vec<PathCheck> = Vec::with_capacity(paths.len());

    let base_snip: Option<String> = match client.get(&base).send().await {
        Ok(r) => {
            if let Ok(b) = r.text().await {
                let s = b.trim();
                if s.is_empty() { None } else { Some(s.chars().take(200).collect()) }
            } else { None }
        }
        Err(_) => None,
    };

    for p in paths.iter() {
        let rel = if p.starts_with('/') { p.clone() } else { format!("/{}", p) };
        let url = format!("{}{}", base, rel);

        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let exists = status.is_success();
                let mut snippet: Option<String> = None;
                if let Ok(body) = resp.text().await {
                    let s = body.trim();
                    if !s.is_empty() {
                        let snippet_trimmed: String = s.chars().take(200).collect();
                        snippet = Some(snippet_trimmed);
                    }
                }

                let mut hints = Vec::new();
                if let Some(ref sn) = snippet {
                    if let Some(ref base_s) = base_snip {
                        if sn == base_s {
                            hints.push("catchall".to_string());
                        }
                    }
                    let s = sn.to_lowercase();
                    if s.contains("<form") { hints.push("login_form".to_string()); }
                    if s.contains("type=\"password\"") { hints.push("password_field".to_string()); }
                    if s.contains("index of /") || s.contains("<title>index of") { hints.push("directory_listing".to_string()); }
                    if s.contains("wp-login.php") || s.contains("wordpress") { hints.push("wp_login".to_string()); }
                    if s.contains("admin") && (s.contains("/admin") || s.contains("administrator")) { hints.push("admin_page".to_string()); }
                }

                if rel == "/.git" || rel == "/.git/" {
                    if let Ok(r2) = client.get(format!("{}{}", base, "/.git/HEAD")).send().await {
                        if r2.status().is_success() {
                            if let Ok(b2) = r2.text().await {
                                let low = b2.to_lowercase();
                                let is_html = low.contains("<!doctype") || low.contains("<html") || low.contains("<head");
                                if !is_html && (low.contains("ref:") || low.contains("refs/")) {
                                    hints.push("git_exposed".to_string());
                                }
                            }
                        }
                    }
                }

                if rel == "/.env" {
                    if let Ok(r2) = client.get(&url).send().await {
                        if r2.status().is_success() {
                            if let Ok(b2) = r2.text().await {
                                let low = b2.to_lowercase();
                                let is_html = low.contains("<!doctype") || low.contains("<html") || low.contains("<head");
                                let looks_like_env = !is_html &&
                                    (low.contains("db_") || low.contains("password") || low.contains("secret") ||
                                    low.contains("api_key") || low.lines().any(|l| l.contains('=') && l.len() < 300));
                                if looks_like_env {
                                    hints.push("env_exposed".to_string());
                                }
                            }
                        }
                    }
                }

                out.push(PathCheck {
                    path: rel,
                    status: status.as_u16(),
                    exists,
                    snippet,
                    hints,
                });
            }
            Err(_) => {
                out.push(PathCheck {
                    path: rel,
                    status: 0,
                    exists: false,
                    snippet: None,
                    hints: Vec::new(),
                });
            }
        }
    }

    Ok(out)
}



pub async fn probe_http(host: &str, port: u16, timeout_secs: u64) -> Result<HttpInfo> {
    let scheme = if port == 443 { "https" } else { "http" };
    let base = format!("{scheme}://{host}:{port}");

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("web_scanner/0.1")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut service_header: Option<String> = None;
    let mut title: Option<String> = None;
    let mut robots: Option<RobotsInfo> = None;
    let mut warnings: Vec<Warning> = Vec::new();
    let mut origin_header: Option<String> = None;

    // main path probe (grab headers + body)
    if let Ok(resp) = client.get(&base).send().await {
        // server header
        if let Some(h) = resp.headers().get(reqwest::header::SERVER) {
            if let Ok(s) = h.to_str() {
                service_header = Some(s.to_string());
                // server header에 버전 노출이 있으면 info
                if s.contains('/') || s.chars().any(|c| c.is_digit(10)) {
                    add_warning(&mut warnings, "info", format!("Server header exposes detail: {}", s), 0.3);
                }
            }
        }

        // X-Powered-By
        if let Some(h) = resp.headers().get("x-powered-by") {
            if let Ok(s) = h.to_str() {
                add_warning(&mut warnings, "info", format!("X-Powered-By header present: {}", s), 0.3);
            }
        }

        // security-related headers
        let has_hsts = resp.headers().get("strict-transport-security").is_some();
        let has_xfo = resp.headers().get("x-frame-options").is_some();
        let has_xcto = resp.headers().get("x-content-type-options").is_some();
        let has_csp = resp.headers().get("content-security-policy").is_some();

        if port == 443 && !has_hsts {
            add_warning(&mut warnings, "warning", "Missing Strict-Transport-Security (HSTS) on HTTPS", 0.8);
        }
        if !has_xfo {
            add_warning(&mut warnings, "warning", "Missing X-Frame-Options header (clickjacking protection)", 0.6);
        }
        if !has_xcto {
            add_warning(&mut warnings, "warning", "Missing X-Content-Type-Options header (nosniff)", 0.6);
        }
        if !has_csp {
            add_warning(&mut warnings, "info", "Missing Content-Security-Policy header", 0.4);
        }

        // Set-Cookie flags 검사 (여러 개 가능)
        let mut set_cookie_vals: Vec<String> = Vec::new();
        for val in resp.headers().get_all(reqwest::header::SET_COOKIE).iter() {
            if let Ok(s) = val.to_str() {
                set_cookie_vals.push(s.to_string());
            }
        }
        if !set_cookie_vals.is_empty() {
            parse_set_cookie_flags(&set_cookie_vals, &mut warnings);
        }
        if let Some(h) = resp.headers().get("access-control-allow-origin") {
            if let Ok(s) = h.to_str() {
                origin_header = Some(s.to_string());
                // wildcard
                if s.trim() == "*" {
                    add_warning(&mut warnings, "warning", "CORS Access-Control-Allow-Origin is '*'", 0.7);
                } else {
                    add_warning(&mut warnings, "info", format!("CORS allowed origin: {}", s), 0.3);
                }
            }
        }

        // credentials header check (dangerous when combined with wildcard)
        if let Some(hc) = resp.headers().get("access-control-allow-credentials") {
            if let Ok(s) = hc.to_str() {
                if s.eq_ignore_ascii_case("true") {
                    // if credentials=true + origin=* -> very bad
                    if origin_header.as_deref() == Some("*") {
                        add_warning(&mut warnings, "critical", "CORS wildcard '*' combined with Access-Control-Allow-Credentials: true — sensitive!", 0.95);
                    } else {
                        add_warning(&mut warnings, "warning", "Access-Control-Allow-Credentials is true", 0.7);
                    }
                }
            }
        }

        // try to read body (may fail)
        if let Ok(body) = resp.text().await {
            if title.is_none() {
                if let Ok(re) = Regex::new("(?is)<title[^>]*>(.*?)</title>") {
                    if let Some(cap) = re.captures(&body) {
                        if let Some(m) = cap.get(1) {
                            title = Some(m.as_str().trim().to_string());
                        }
                    }
                }
            }
        }
    }

    // robots.txt probe (quick)
    let robots_url = format!("{}/robots.txt", base);
    match client.get(&robots_url).send().await {
        Ok(r) => {
            let status = r.status();
            let exists = status.is_success();
            let mut snippet = None;
            if exists {
                if let Ok(body) = r.text().await {
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
        warnings,
    })
}
