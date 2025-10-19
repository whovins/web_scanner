use colored::*;
use atty::Stream;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn colors_enabled() -> bool {
    // TTY이고 NO_COLOR가 꺼져 있으면 색 사용
    atty::is(Stream::Stdout) && std::env::var_os("NO_COLOR").is_none()
}

pub fn print_banner() {
    let art = r#"
     /\_/\   Cl0ckC@k
    ( o.o )  Simple Port Scanner
     > ^ <   🐾  Comprehensive Scanning
    "#;

    if colors_enabled() {
        println!("{}", art.cyan());
        println!("{}  {}", "Cl0ckC@k".bold(), format!("v{}", VERSION).magenta());
        println!("{}", "🐾 Follow the trail, find the port...".yellow());
    } else {
        println!("{art}");
        println!("Cl0ckC@k v{VERSION}");
        println!("🐾 Follow the trail, find the port...");
    }

    // 진행바가 바로 아래서 시작되도록 한 줄 띄우기
    println!();
}
