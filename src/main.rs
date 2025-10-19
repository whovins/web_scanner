use serde::Serialize;

use std::path::Path;
use std::sync::Arc;

use indicatif::{ProgressBar, ProgressStyle};

mod scanner;
use scanner::port::{parse_ports, scan_port};
use scanner::services;
use scanner::vuln_db;
mod banner;
use futures::StreamExt;
use clap::{Parser, ArgGroup};



//
// ───────────────────────────────── CLI ────────────────────────────────────────
//
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Simple Port Scanner with HTTP passive checks, path discovery and summary report",
)]
#[command(group(
    ArgGroup::new("targeting")
        .required(true)               // 둘 중 하나는 반드시 있어야 함
        .args(&["host", "targets"])
))]
struct Cli {
    #[arg(short = 't', long)]
    host: Option<String>,             // <== Option 으로 변경

    /// 대상 목록 파일(one per line: host/ip/cidr, # 주석 허용)
    #[arg(long)]
    targets: Option<String>,
    /// 포트 지정. 예: 80,443,8000-8100
    #[arg(short = 'p', long)]
    ports: String,

    /// 글로벌 동시 연결 수
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// 커넥트 타임아웃(초). 1..=60
    #[arg(
        long,
        default_value_t = 2,
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    timeout: u64,

    /// 결과 저장 파일(.json | .csv | .ndjson)
    #[arg(short = 's', long)]
    save: Option<String>,

    /// HTTP 패시브 점검 수행
    #[arg(
        long,
        help = "If set, perform lightweight HTTP probe on likely HTTP ports (use --http-ports to control which ports)"
    )]
    http_probe: bool,

    /// HTTP로 간주할 포트 목록
    #[arg(
        long,
        default_value = "80,443,8080,8000,8888",
        help = "Comma/list or ranges of ports to consider HTTP for probing. e.g. 80,443,3000-3010"
    )]
    http_ports: String,

    /// 공통 경로 점검 수행
    #[arg(
        long,
        help = "If set, check a small list of common paths (e.g. /admin, /login). Use --paths to customize."
    )]
    check_paths: bool,

    /// 점검할 경로 목록
    #[arg(
        long,
        default_value = "/admin,/login,/.git,/.env,/.svn,.htaccess,/config.php,/wp-login.php,/robots.txt",
        help = "Comma-separated list of paths to check (relative paths)."
    )]
    paths: String,

    /// 로컬 취약 징후 룰 JSON 파일 경로(선택)
    #[arg(long, help = "Optional local vuln DB JSON file to load rules from")]
    vuln_db: Option<String>,

    /// 제외 목록 파일(one per line: ip/cidr, # 주석 허용)
    #[arg(long)]
    exclude: Option<String>,

    /// 초당 시도 상한(토큰버킷)
    #[arg(long, default_value_t = 300)]
    rate: u32,

    /// 호스트당 동시 연결 상한
    #[arg(long, default_value_t = 20)]
    max_conns_per_host: usize,

    /// 실패 재시도 횟수(현재 connect 타임아웃에만 적용)
    #[arg(long, default_value_t = 1)]
    retries: u8,

    /// DNS 리졸브 타임아웃
    #[arg(long, default_value = "1s")]
    resolve_timeout: humantime::Duration,

    /// 커스텀 DNS 서버(콤마로 구분된 IP 목록)
    #[arg(long)]
    dns_servers: Option<String>,
    #[arg(long, help = "Only Open port number to save")]
    only_open: bool,
}

//
// ─────────────────────────────── 데이터 구조 ─────────────────────────────────
//
#[derive(Serialize, Clone)]
struct ScanRecord {
    host: String, // 스캔에 사용한 IP 문자열(표시용)
    port: u16,
    open: bool,
    service: Option<String>,
    title: Option<String>,
    warnings: Vec<scanner::http::Warning>,
    paths: Vec<scanner::http::PathCheck>,
    banner: Option<String>,        // 앞부분(최대 160자 정도만 저장)
    banner_sha1: Option<String>,
    tls: Option<scanner::tls::TlsInfo>,
    proto_hits: Vec<scanner::proto::ProtoHit>,
}

/// 단일 호스트 요약
#[derive(Serialize, Clone)]
struct Summary {
    host: String,
    total_ports_scanned: usize,
    open_ports: usize,
    warnings_info: usize,
    warnings_warning: usize,
    warnings_critical: usize,
    total_paths_checked: usize,
    paths_found: usize,
    paths_suspected: usize,
}

#[derive(Serialize, Clone)]
struct FullReport {
    summary: Summary,
    records: Vec<ScanRecord>,
}

//
// ─────────────────────────────── 저장 유틸 ───────────────────────────────────
//


fn save_csv(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(&[
        "host",
        "port",
        "open",
        "service",
        "title",
        "warnings",
        "paths",
        "banner",
        "banner_sha1"
    ])?;
    for r in records {
        let warnings_json =
            serde_json::to_string(&r.warnings).unwrap_or_else(|_| "[]".to_string());
        let paths_json = serde_json::to_string(&r.paths).unwrap_or_else(|_| "[]".to_string());
        wtr.serialize((
            &r.host, r.port, r.open,
            r.service.as_deref().unwrap_or(""),
            r.title.as_deref().unwrap_or(""),
            &warnings_json, &paths_json,
            r.banner.as_deref().unwrap_or(""),
            r.banner_sha1.as_deref().unwrap_or(""),
        ))?;
    }
    wtr.flush()?;
    Ok(())
}

fn save_json(path: &str, summary: &Summary, records: &[ScanRecord]) -> anyhow::Result<()> {
    let report = FullReport {
        summary: summary.clone(),
        records: records.to_vec(),
    };
    std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

fn save_ndjson(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    let mut f = std::fs::File::create(path)?;
    for r in records {
        let line = serde_json::to_string(r)?;
        use std::io::Write;
        writeln!(f, "{}", line)?;
    }
    Ok(())
}

fn save_results(path: &str, summary: &Summary, records: &[ScanRecord]) -> anyhow::Result<()> {
    let lower = path.to_lowercase();
    if lower.ends_with(".json") {
        save_json(path, summary, records)
    } else if lower.ends_with(".csv") {
        save_csv(path, records)
    } else if lower.ends_with(".ndjson") {
        // 요약은 별도 필요시 summary.json으로 저장 권장
        save_ndjson(path, records)
    } else {
        anyhow::bail!("지원하지 않는 확장자입니다. .json / .csv / .ndjson 사용하세요.");
    }
}

fn parse_paths(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

//
// ───────────────────────────────── main ──────────────────────────────────────
//
#[tokio::main]
async fn main() {
    use trust_dns_resolver::config::*;
    use trust_dns_resolver::TokioAsyncResolver;

    // 1) CLI 파싱
    let cli = Cli::parse();
    #[cfg(not(test))]
    banner::print_banner();

    // 2) DNS 리졸버 구성
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(2);
    let cfg = if let Some(list) = cli.dns_servers.as_deref() {
        let mut group = NameServerConfigGroup::default();
        for ip in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let ip: std::net::IpAddr = ip.parse().expect("invalid dns server ip");
            group.push(NameServerConfig {
                socket_addr: std::net::SocketAddr::new(ip, 53),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }
        ResolverConfig::from_parts(None, vec![], group)
    } else {
        ResolverConfig::default()
    };
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(cfg, opts);


    let inline_targets: Vec<String> = match (&cli.host, &cli.targets) {
        (Some(h), None) => vec![h.clone()],
        _ => vec![],
    };

    let specs = scanner::targets::load_targets(
        &inline_targets,
        cli.targets.as_deref().map(Path::new),
    )
    .expect("load targets");

    let excludes =
        scanner::targets::load_excludes(cli.exclude.as_deref().map(Path::new)).expect("load excludes");

    let resolved = scanner::targets::resolve_all(
        &specs,
        &excludes,
        &resolver,
        (*cli.resolve_timeout).into(),
        None, // seed (옵션)
    )
    .await
    .expect("resolve targets");

    if resolved.is_empty() {
        eprintln!("no targets to scan after applying excludes; exiting");
        return;
    }

    // 4) 레이트리밋
    let limiters =
        scanner::rate::Limiters::new(cli.rate, cli.concurrency, cli.max_conns_per_host);

    // 5) 공통 파싱(한번만)
    let ports = parse_ports(&cli.ports).expect("ports parse error");
    let http_ports_vec = parse_ports(&cli.http_ports).expect("http_ports parse error");
    let http_paths_vec = parse_paths(&cli.paths);

    let vuln_rules = if let Some(p) = cli.vuln_db.as_deref() {
        match vuln_db::load_rules_from_file(p) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "failed to load vuln db '{}': {}. Using defaults.",
                    p, e
                );
                vuln_db::default_rules()
            }
        }
    } else {
        vuln_db::default_rules()
    };

    // 6) 다중 타깃 스캔 루프
    for tgt in &resolved {
        let host_ip = tgt.ip.to_string();
        println!("====================");
        println!(
            "스캔 대상: {} ({}) — ports={}, concurrency={}",
            tgt.display,
            host_ip,
            ports.len(),
            cli.concurrency
        );

        // 진행바(호스트별)
        let total = ports.len() as u64;
        let pb = Arc::new(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        let pb_clone = pb.clone();

        // (1) 포트 스캔 (레이트리밋 적용)
        let results = futures::stream::iter(ports.clone())
            .map(|port| {
                let host_ip = host_ip.clone();
                let to = cli.timeout;
                let pb_local = pb_clone.clone();
                let lim = &limiters;
                let ip_for_bucket = tgt.ip; // per-host limiter key
                async move {
                    // global rate + per-host concurrency 토큰
                    lim.acquire(&ip_for_bucket).await;
                    let open = scan_port(&host_ip, port, to).await;
                    pb_local.inc(1);
                    (port, open)
                }
            })
            .buffer_unordered(cli.concurrency)
            .collect::<Vec<(u16, bool)>>()
            .await;

        pb.finish_with_message("port scan complete");

        // (2) 정렬
        let mut sorted = results;
        sorted.sort_by_key(|(p, _)| *p);

        // (3) 레코드/후처리
        let mut records: Vec<ScanRecord> = Vec::new();

        for (port, open) in &sorted {
            let mut service_hint = services::well_known_service_owned(*port);
            let mut title: Option<String> = None;
            let mut warnings_out: Vec<scanner::http::Warning> = Vec::new();
            let mut paths_out: Vec<scanner::http::PathCheck> = Vec::new();

            let mut banner_opt: Option<String> = None;
            let mut banner_sha1_opt: Option<String> = None;
            fn truncate(s: &str, max: usize) -> String {
                if s.len() <= max { s.to_string() } else { s.chars().take(max).collect() }
            }
            if *open && !http_ports_vec.contains(port) {
                if let Ok(Some(bi)) = scanner::banner::grab_banner(&host_ip, *port, cli.timeout).await {
                    banner_opt = Some(truncate(&bi.banner, 160));
                    banner_sha1_opt = Some(bi.banner_sha1);
                    // 배너에서 추론된 서비스가 있으면 힌트 보강
                    if service_hint.is_none() {
                        service_hint = bi.service_guess;
                    }
                }
            }

            let mut proto_hits: Vec<scanner::proto::ProtoHit> = Vec::new();

            if *open {
                match *port {
                    6379 => if let Ok(Some(h)) = scanner::proto::probe_redis(&host_ip, *port, cli.timeout).await { proto_hits.push(h); },
                    3306 => if let Ok(Some(h)) = scanner::proto::probe_mysql(&host_ip, *port, cli.timeout).await { proto_hits.push(h); },
                    5432 => if let Ok(Some(h)) = scanner::proto::probe_postgres(&host_ip, *port, cli.timeout).await { proto_hits.push(h); },
                    3389 => if let Ok(Some(h)) = scanner::proto::probe_rdp(&host_ip, *port, cli.timeout).await { proto_hits.push(h); },
                    445  => if let Ok(Some(h)) = scanner::proto::probe_smb(&host_ip, *port, cli.timeout).await { proto_hits.push(h); },
                    _ => {}
                }
            }

            let mut tls_info_opt: Option<scanner::tls::TlsInfo> = None;

            if *open && http_ports_vec.contains(port) {
                // SNI 호스트 결정: 원본이 도메인이면 그걸 쓰고, 아니면 IP 사용
                let sni_host = match tgt.display.parse::<std::net::IpAddr>() {
                    Ok(_) => host_ip.as_str(),
                    Err(_) => tgt.display.as_str(),
                };
            if *open && matches!(*port, 443 | 8443 | 9443 | 10443) {
                    if let Ok(Some(ti)) = scanner::tls::probe_tls(sni_host, &host_ip, *port, cli.timeout).await {
                        // 가벼운 경고 예시(알려지지 않은 ALPN)
                        if let Some(alpn) = &ti.alpn {
                            if alpn != "h2" && alpn != "http/1.1" {
                                warnings_out.push(scanner::http::Warning { level: "info".into(), message: format!("Unknown ALPN: {}", alpn), confidence: 0.4 });
                            }
                        }
                        tls_info_opt = Some(ti);
                    }
                }
            }

            // SSH: 22/tcp 열려있으면 배너 파싱
            if *open && *port == 22 {
                if let Ok(Some(ssh)) = scanner::proto::ssh::probe_ssh(&host_ip, *port, cli.timeout).await {
                    if service_hint.is_none() {
                        service_hint = Some("ssh".into());
                    }
                    // 배너를 record.banner에도 남길 수 있음
                    banner_opt.get_or_insert(ssh.raw.clone());

                    // 약식 취약 룰(예시)
                    if let (Some(prod), Some(ver)) = (&ssh.product, &ssh.version) {
                        if prod.eq_ignore_ascii_case("openssh") {
                            // 아주 단순한 구버전 감지 예시
                            let is_old = ver.starts_with('6') || ver.starts_with("7.0")
                                || ver.starts_with("7.1") || ver.starts_with("7.2") || ver.starts_with("7.3");
                            if is_old {
                                warnings_out.push(scanner::http::Warning{
                                    level: "warning".into(),
                                    message: format!("OpenSSH {} is old — review upgrade notes", ver),
                                    confidence: 0.6,
                                });
                            }
                        }
                    }

                    // note: Option<String> 맞추기
                    let note_string = format!(
                        "{} {}",
                        ssh.product.clone().unwrap_or_default(),
                        ssh.version.clone().unwrap_or_default()
                    )
                    .trim()
                    .to_string();
                    let note_opt = if note_string.is_empty() { None } else { Some(note_string) };

                    proto_hits.push(scanner::proto::ProtoHit {
                        name: "ssh".into(),
                        note: note_opt, // <- Option<String>
                    });
                }
            }

            

            // HTTP 패시브 점검
            if cli.http_probe && *open && http_ports_vec.contains(port) {
                match scanner::http::probe_http(&host_ip, *port, cli.timeout).await {
                    
                    Ok(info) => {
                        if !info.warnings.is_empty() {
                            println!("    warnings ({}):", info.warnings.len());
                            for w in &info.warnings {
                                println!(
                                    "      - [{}] {} (confidence={})",
                                    w.level, w.message, w.confidence
                                );
                            }
                        }
                        
                        if let Some(robots) = &info.robots {
                            if robots.exists {
                                println!(
                                    "    robots.txt (port {}): status={} snippet={}",
                                    port,
                                    robots.status,
                                    robots.body_snippet.as_deref().unwrap_or("")
                                );
                            } else if robots.status != 0 {
                                println!(
                                    "    robots.txt (port {}): status={}",
                                    port, robots.status
                                );
                            }
                        }

                        // vuln_db 룰 매칭 (service/title)
                        let service_clone = info.service.clone();
                        let title_clone = info.title.clone();

                        let mut mapped: Vec<scanner::http::Warning> = Vec::new();
                        mapped.extend(vuln_db::match_vulns(service_clone.as_deref(), &vuln_rules, "service"));

                        mapped.extend(vuln_db::match_vulns(title_clone.as_deref(), &vuln_rules, "title"));

                         if let Some(sec) = &info.security {
                            let header_blob = [
                                sec.server.as_deref().unwrap_or(""),
                                sec.x_powered_by.as_deref().unwrap_or(""),
                                sec.csp.as_deref().unwrap_or(""),
                            ].join(" | ");
                            mapped.extend(vuln_db::match_vulns(Some(&header_blob), &vuln_rules, "header"));
                        }

                        if !mapped.is_empty() {
                            println!("    vuln db matches ({}):", mapped.len());
                            for w in &mapped {
                                println!(
                                    "      - [{}] {} (confidence={})",
                                    w.level, w.message, w.confidence
                                );
                            }
                        }
                       

                        if let Some(s) = service_clone {
                            service_hint = Some(s);
                        }
                        title = title_clone;

                        warnings_out = info.warnings;
                        warnings_out.extend(mapped);
                    }
                    Err(e) => {
                        eprintln!("http probe failed for {}:{} -> {}", &host_ip, port, e);
                    }
                }

                // 공통 경로 점검
                if cli.check_paths {
                    match scanner::http::probe_paths(
                        &host_ip,
                        *port,
                        cli.timeout,
                        &http_paths_vec,
                    )
                    .await
                    {
                        Ok(pres) => {
                            for pc in &pres {
                                if pc.exists {
                                    println!(
                                        "    path {} -> {} (snippet={})",
                                        pc.path,
                                        pc.status,
                                        pc.snippet.as_deref().unwrap_or("")
                                    );
                                } else if pc.status != 0 {
                                    println!("    path {} -> {}", pc.path, pc.status);
                                } else {
                                    println!("    path {} -> unreachable/timeout", pc.path);
                                }

                                if !pc.hints.is_empty() {
                                    println!("      hints: {}", pc.hints.join(", "));
                                    let is_catchall =
                                        pc.hints.iter().any(|h| h == "catchall");
                                    for hint in &pc.hints {
                                        match hint.as_str() {
                                            "git_exposed_verified" => {
                                                warnings_out.push(scanner::http::Warning {
                                                    level: "critical".to_string(),
                                                    message: format!("Git metadata exposed at {}", pc.path),
                                                    confidence: 0.95,
                                                });
                                            }
                                            // 혹시 다른 로직에서 git_exposed가 들어올 수 있다면 낮춰서 처리
                                            "git_exposed" => {
                                                warnings_out.push(scanner::http::Warning {
                                                    level: "warning".to_string(),
                                                    message: format!("Possible git metadata exposure at {} (needs manual verify)", pc.path),
                                                    confidence: 0.5,
                                                });
                                            }
                                            "env_exposed" => {
                                                if is_catchall {
                                                    warnings_out.push(scanner::http::Warning {
                                                        level: "warning".to_string(),
                                                        message: format!("Potential .env content at {} (server returns default page — manual check advised)", pc.path),
                                                        confidence: 0.45,
                                                    });
                                                } else {
                                                    warnings_out.push(scanner::http::Warning {
                                                        level: "critical".to_string(),
                                                        message: format!(".env content appears exposed at {}", pc.path),
                                                        confidence: 0.9,
                                                    });
                                                }
                                            }
                                            "directory_listing" => {
                                                warnings_out.push(scanner::http::Warning {
                                                    level: "warning".to_string(),
                                                    message: format!(
                                                        "Directory listing detected at {}",
                                                        pc.path
                                                    ),
                                                    confidence: 0.85,
                                                });
                                            }
                                            "password_field" | "login_form" => {
                                                let lvl = if is_catchall { "info" } else { "warning" };
                                                let conf = if is_catchall { 0.35 } else { 0.7 };
                                                warnings_out.push(scanner::http::Warning {
                                                    level: lvl.to_string(),
                                                    message: format!("Login or password field found at {}", pc.path),
                                                    confidence: conf,
                                                });
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            paths_out = pres;
                        }
                        Err(e) => {
                            eprintln!("path probe failed for {}:{} -> {}", &host_ip, port, e);
                        }
                    }
                }
            }

            // 콘솔 출력(간단)
            if let Some(ref s) = service_hint {
                if let Some(ref t) = title {
                    println!(
                        "{:>5}/tcp\t{}\t({})\ttitle=\"{}\"",
                        port,
                        if *open { "open" } else { "closed" },
                        s,
                        t
                    );
                } else {
                    println!(
                        "{:>5}/tcp\t{}\t({})",
                        port,
                        if *open { "open" } else { "closed" },
                        s
                    );
                }
            } else {
                println!("{:>5}/tcp\t{}", port, if *open { "open" } else { "closed" });
            }

            if service_hint.is_none() && !proto_hits.is_empty() {
                if let Some(first) = proto_hits.first() {
                    service_hint = Some(first.name.clone()); // "postgres", "redis", "memcached" 등
                }
            }
            
            if *open {
                records.push(ScanRecord {
                    host: host_ip.clone(),
                    port: *port,
                    open: true, // 열린 포트만 push 중이라면 true 고정
                    service: service_hint,
                    title,
                    warnings: warnings_out,
                    paths: paths_out,
                    banner: banner_opt,
                    banner_sha1: banner_sha1_opt,
                    tls: tls_info_opt,
                    proto_hits, 
                });
            }
        }

        records.retain(|r| r.open);
        
        

        // (4) 요약 집계(호스트 단위)
        let total_ports_scanned = sorted.len();
        let open_ports = records.iter().filter(|r| r.open).count();
        let mut warnings_info = 0usize;
        let mut warnings_warning = 0usize;
        let mut warnings_critical = 0usize;
        let total_paths_checked: usize = records.iter().map(|r| r.paths.len()).sum();
        let paths_found: usize =
            records.iter().map(|r| r.paths.iter().filter(|p| p.exists).count()).sum();

        for r in &records {
            for w in &r.warnings {
                match w.level.as_str() {
                    "info" => warnings_info += 1,
                    "warning" => warnings_warning += 1,
                    "critical" => warnings_critical += 1,
                    _ => warnings_info += 1,
                }
            }
        }

        let paths_suspected: usize = records
            .iter()
            .map(|r| {
                r.paths
                    .iter()
                    .filter(|p| {
                        p.exists
                            && !p.hints.iter().any(|h| h == "catchall")
                            && p.hints.iter().any(|h| {
                                h == "env_exposed" || h == "git_exposed" || h == "directory_listing"
                            })
                    })
                    .count()
            })
            .sum();

        let summary = Summary {
            host: host_ip.clone(),
            total_ports_scanned,
            open_ports,
            warnings_info,
            warnings_warning,
            warnings_critical,
            total_paths_checked,
            paths_found,
            paths_suspected,
        };

        // (5) 콘솔 요약
        println!("\n=== Scan Summary ===");
        println!("Host: {}", summary.host);
        println!(
            "Ports scanned: {} (open: {})",
            summary.total_ports_scanned, summary.open_ports
        );
        println!(
            "Warnings: info={} warning={} critical={}",
            summary.warnings_info, summary.warnings_warning, summary.warnings_critical
        );
        println!(
            "Paths checked: {} (found: {}) suspected: {}",
            summary.total_paths_checked, summary.paths_found, summary.paths_suspected
        );
        println!("====================\n");

        // (6) 저장 — 다중 타깃일 때는 파일명에 IP suffix 자동 부여
       if let Some(base) = &cli.save {
            // 확장자 앞에 -<ip> 삽입 (다중 타깃인 경우)
            let out = if resolved.len() > 1 {
                match base.rsplit_once('.') {
                    Some((stem, ext)) => format!("{}-{}.{}", stem, host_ip.replace(':', "_"), ext),
                    None => format!("{}-{}", base, host_ip.replace(':', "_")),
                }
            } else {
                base.clone()
            };

            // 이미 open 인 것만 push 하고 있으니 사실상 그대로 records.clone() 과 동일
            let records_for_export: Vec<ScanRecord> = records.clone();

            if let Err(e) = save_results(&out, &summary, &records_for_export) {
                eprintln!("저장 실패: {}", e);
            } else {
                println!("저장 완료: {}", out);
            }
        }
    }
}
