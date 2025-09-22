use clap::Parser;

mod scanner;
use scanner::port::{scan_port, parse_ports};
use futures::{StreamExt, stream};
use serde::Serialize;

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
}
#[derive(Serialize)]
struct ScanRecord {
    host: String,
    port: u16,
    open: bool,
}
fn save_csv(path: &str, records: &[ScanRecord]) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(&["host","port","open"])?; // 헤더
    for r in records {
        // (host, port, open) 튜플로 직렬화 → 임시 &String 문제 없음
        wtr.serialize((&r.host, r.port, r.open))?;
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
        if *open {
            println!("Port {} is OPEN", port);
        } else {
            println!("Port {} is CLOSED", port);
        }
        records.push(ScanRecord {
            host: cli.host.clone(),
            port: *port,
            open: *open,
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