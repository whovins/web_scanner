use clap::Parser;

mod scanner;
use scanner::port::{scan_port, parse_ports};
use futures::{StreamExt, stream};

#[derive(Parser, Debug)]
#[command(author, version, about="Simple Port Scanner")]
struct Cli {
    #[arg(short='t', long)]
    host: String,

    #[arg(short, long)]
    ports: String,

    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
    timeout: u64,
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
    for(port, open) in sorted {
        if open {
            println!("Port {} is OPEN", port);
        } else {
            println!("Port {} is CLOSED", port);
        }
    }
}