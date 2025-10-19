// src/scanner/http.rs
use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

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
    pub security: Option<SecurityHeaders>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RobotsInfo {
    pub exists: bool,
    pub status: u16,
    pub body_snippet: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SecurityHeaders {
    pub hsts: Option<String>,              // Strict-Transport-Security
    pub csp: Option<String>,               // Content-Security-Policy
    pub x_frame_options: Option<String>,   // X-Frame-Options
    pub x_content_type_options: Option<String>, // X-Content-Type-Options
    pub referrer_policy: Option<String>,   // Referrer-Policy
    pub permissions_policy: Option<String>,// Permissions-Policy
    pub server: Option<String>,            // Server
    pub x_powered_by: Option<String>,      // X-Powered-By
}

const SNIP_PATH: usize = 200;
const SNIP_ROBOTS: usize = 512;

fn push_unique(warns: &mut Vec<Warning>, seen: &mut HashSet<String>, level: &str, msg: &str, conf: f32) {
    if seen.insert(format!("{}|{}", level, msg)) {
        warns.push(Warning { level: level.into(), message: msg.into(), confidence: conf });
    }
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
    // if s.contains(".git") || s.contains("git/") || s.contains("ref: refs/heads") {
    //     hints.push("git_exposed".to_string());
    // }
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

fn parse_set_cookie_flags(set_cookie_vals: &[String], warnings: &mut Vec<Warning>) {
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
                if s.is_empty() { None } else { Some(s.chars().take(SNIP_PATH).collect()) }
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
                let mut exists = status.is_success() || status.is_redirection();
                let mut status_u16 = status.as_u16();
                let mut snippet: Option<String> = None;
                if let Ok(body) = resp.text().await {
                    let s = body.trim();
                    if !s.is_empty() {
                        let snippet_trimmed: String = s.chars().take(SNIP_PATH).collect();
                        snippet = Some(snippet_trimmed);
                    }
                }

                let mut hints = Vec::new();
                if let Some(ref sn) = snippet {
                    if let Some(ref base_s) = base_snip {
                        if sn == base_s { hints.push("catchall".to_string()); }
                    }
                    hints.extend(analyze_snippet(sn));
                }


               if rel == "/.git" || rel == "/.git/" {
                    if let Ok(r2) = client.get(format!("{}{}", base, "/.git/HEAD")).send().await {
                        if r2.status().is_success() {
                            if let Ok(b2) = r2.text().await {
                                let low = b2.to_lowercase();
                                let is_html = low.contains("<!doctype") || low.contains("<html") || low.contains("<head");
                                if !is_html && (low.contains("ref:") || low.contains("refs/")) {
                                    hints.push("git_exposed_verified".to_string());
                                    exists = true;
                                    status_u16 = 200;
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
                    status: status_u16,   
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
    let mut seen = HashSet::new();
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
    let mut security_opt: Option<SecurityHeaders> = None;



    // main path probe (grab headers + body)
    if let Ok(resp) = client.get(&base).send().await {
        // 헤더/URL은 body 읽기 전에 복제해서 보관
        let headers = resp.headers().clone();
        let final_url = resp.url().clone();

        // server header
        if let Some(h) = headers.get(reqwest::header::SERVER) {
            if let Ok(s) = h.to_str() {
                service_header = Some(s.to_string());
                // server header에 버전 노출이 있으면 info
                if s.contains('/') || s.chars().any(|c| c.is_ascii_digit()) {
                    add_warning(&mut warnings, "info", format!("Server header exposes detail: {}", s), 0.3);
                }
            }
        }

        // X-Powered-By
        if let Some(h) = headers.get("x-powered-by") {
            if let Ok(s) = h.to_str() {
                add_warning(&mut warnings, "info", format!("X-Powered-By header present: {}", s), 0.3);
            }
        }

        // security-related headers
        let has_hsts = headers.get("strict-transport-security").is_some();
        let has_xfo  = headers.get("x-frame-options").is_some();
        let has_xcto = headers.get("x-content-type-options").is_some();
        let has_csp  = headers.get("content-security-policy").is_some();

       if port == 443 && !has_hsts {
            push_unique(&mut warnings, &mut seen, "warning", "Missing Strict-Transport-Security (HSTS) on HTTPS", 0.8);
        }
        if !has_xfo {
            push_unique(&mut warnings, &mut seen, "warning", "Missing X-Frame-Options header (clickjacking protection)", 0.6);
        }
        if !has_xcto {
            push_unique(&mut warnings, &mut seen, "warning", "Missing X-Content-Type-Options header (nosniff)", 0.6);
        }
        if !has_csp {
            push_unique(&mut warnings, &mut seen, "info", "Missing Content-Security-Policy header", 0.4);
        }
        // Set-Cookie flags 검사 (여러 개 가능)
        let mut set_cookie_vals: Vec<String> = Vec::new();
        for val in headers.get_all(reqwest::header::SET_COOKIE).iter() {
            if let Ok(s) = val.to_str() {
                set_cookie_vals.push(s.to_string());
            }
        }
        if !set_cookie_vals.is_empty() {
            parse_set_cookie_flags(&set_cookie_vals, &mut warnings);
        }

        // CORS
        if let Some(h) = headers.get("access-control-allow-origin") {
            if let Ok(s) = h.to_str() {
                origin_header = Some(s.to_string());
                if s.trim() == "*" {
                    add_warning(&mut warnings, "warning", "CORS Access-Control-Allow-Origin is '*'", 0.7);
                } else {
                    add_warning(&mut warnings, "info", format!("CORS allowed origin: {}", s), 0.3);
                }
            }
        }
        if let Some(hc) = headers.get("access-control-allow-credentials") {
            if let Ok(s) = hc.to_str() {
                if s.eq_ignore_ascii_case("true") {
                    if origin_header.as_deref() == Some("*") {
                        add_warning(
                            &mut warnings,
                            "critical",
                            "CORS wildcard '*' combined with Access-Control-Allow-Credentials: true — sensitive!",
                            0.95,
                        );
                    } else {
                        add_warning(&mut warnings, "warning", "Access-Control-Allow-Credentials is true", 0.7);
                    }
                }
            }
        }

        // body에서 <title> 추출
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

        // 보안 헤더 구조 채우기
        let sec = SecurityHeaders {
            hsts: headers.get("strict-transport-security").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            csp: headers.get("content-security-policy").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            x_frame_options: headers.get("x-frame-options").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            x_content_type_options: headers.get("x-content-type-options").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            referrer_policy: headers.get("referrer-policy").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            permissions_policy: headers.get("permissions-policy").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            server: headers.get("server").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            x_powered_by: headers.get("x-powered-by").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
        };

        
        
        

        // 간단 규칙 (Warning::… 대신 add_warning 사용)
       let is_https = final_url.scheme() == "https" || scheme == "https";
        // if is_https && sec.hsts.is_none() {
        //     push_unique(&mut warnings, &mut seen, "warning", "HSTS not set on HTTPS origin", 0.7);
        // }
        // if sec.csp.is_none() {
        //     push_unique(&mut warnings, &mut seen, "info", "CSP not set", 0.4);
        // }
        // if sec.x_frame_options.is_none() {
        //     push_unique(&mut warnings, &mut seen, "warning", "X-Frame-Options missing (clickjacking risk)", 0.7);
        // }
        // if sec.x_content_type_options.as_deref() != Some("nosniff") {
        //     push_unique(&mut warnings, &mut seen, "info", "X-Content-Type-Options not 'nosniff'", 0.5);
        // }
       if let Some(loc) = headers.get("location").and_then(|v| v.to_str().ok()) {
            if is_https && loc.starts_with("http://") {
                push_unique(&mut warnings, &mut seen, "critical", "HTTPS to HTTP downgrade redirect", 0.9);
            }
        }

        security_opt = Some(sec);
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
                    snippet = Some(s.chars().take(SNIP_ROBOTS).collect());
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
    warnings.sort_by(|a,b| a.level.cmp(&b.level).then(a.message.cmp(&b.message)));
    warnings.dedup_by(|a,b| a.level == b.level && a.message == b.message);
    Ok(HttpInfo {
        service: service_header,
        title,
        robots,
        warnings,
        security: security_opt, // ← 누락되면 컴파일 에러
    })
  

}

