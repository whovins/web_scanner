use clap::Parser;

mod scanner;
use scanner::port::{scan_port, parse_ports};
use scanner::services;
use futures::{StreamExt, stream};
use serde::Serialize;
use anyhow::Result; 

#[derive(Parser, Debug)]
#[command(author, version, about="Simple Port Scanner")]
struct Cli {
    #[arg(short='t', long)]
    host: String,

    #[arg(short='p', long)]
    ports: String,

    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    timeout: u64,

    #[arg(short='s', long)]
    save: Option<String>,

    #[arg(long, help = "If set, perform lightweight HTTP probe on likely HTTP ports (80,443,8080,8000,8888)")]
    http_probe: bool,
}

#[derive(Serialize)]
struct ScanRecord {
    host: String,
    port: u16,
    open: bool,
    service: Option<String>,
    title: Option<String>,
}

fn save_csv(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(&["host","port","open","service","title"])?; // 헤더
    for r in records {
        wtr.serialize((
            &r.host,
            r.port,
            r.open,
            r.service.as_deref().unwrap_or(""),
            r.title.as_deref().unwrap_or(""),
        ))?;
    }
    wtr.flush()?;
    Ok(())
}

fn save_json(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(records)?)?;
    Ok(())
}

fn save_results(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    let lower = path.to_lowercase();
    if lower.ends_with(".json") {
        save_json(path, records)
    } else if lower.ends_with(".csv") {
        save_csv(path, records)
    } else {
        anyhow::bail!("지원하지 않는 확장자입니다. .json 또는 .csv 사용하세요.");
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let ports = match parse_ports(&cli.ports) {
        Ok(v) => v,
        Err(e) => {
            eprint!("ports parse error: {}", e);
            std::process::exit(1);
        }
    };

    println!("Scanning host: {} ({} ports, concurrency={})", cli.host, ports.len(), cli.concurrency);

    let results = stream::iter(ports)
        .map(|port| {
            let host = cli.host.clone();
            let to = cli.timeout;
            async move {
                let open = scan_port(&host, port, to).await;
                (port, open)
            }
        })
        .buffer_unordered(cli.concurrency)
        .collect::<Vec<(u16, bool)>>()
        .await;

    let mut sorted = results;
    sorted.sort_by_key(|(p, _)| *p);

    let mut records: Vec<ScanRecord> = Vec::new();

    for (port, open) in &sorted {
        let mut service_hint = services::well_known_service_owned(*port);

        let mut title: Option<String> = None;

        if cli.http_probe && *open && matches!(*port, 80 | 443 | 8080 | 8000 | 8888) {
            match scanner::http::probe_http(&cli.host, *port, cli.timeout).await {
                Ok(info) => {
                    if let Some(s) = info.service {
                        service_hint = Some(s);
                    }
                    title = info.title;
                   if let Some(robots) = info.robots {
                        if robots.exists {
                            println!("    robots.txt (port {}): status={} snippet={}",
                                port,
                                robots.status,
                                robots.body_snippet.as_deref().unwrap_or("")
                            );
                        } else if robots.status != 0 {
                            println!("    robots.txt (port {}): status={}", port, robots.status);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("http probe failed for {}:{} -> {}", &cli.host, port, e);
                }
            }
        }

        if let Some(ref s) = service_hint {
            if let Some(ref t) = title {
                println!("{:>5}/tcp\t{}\t({})\ttitle=\"{}\"", port, if *open { "open" } else { "closed" }, s, t);
            } else {
                println!("{:>5}/tcp\t{}\t({})", port, if *open { "open" } else { "closed" }, s);
            }
        } else {
            println!("{:>5}/tcp\t{}", port, if *open { "open" } else { "closed" });
        }

        records.push(ScanRecord {
            host: cli.host.clone(),
            port: *port,
            open: *open,
            service: service_hint,
            title,
        });
    }

    if let Some(path) = &cli.save {
        if let Err(e) = save_results(path, &records) {
            eprintln!("저장 실패: {}", e);
        } else {
            println!("저장 완료: {}", path);
        }
    }
}
