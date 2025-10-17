// src/scanner/targets.rs
use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{fs::File, io::{BufRead, BufReader}, net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::Path, time::Duration};
use trust_dns_resolver::{TokioAsyncResolver, name_server::GenericConnector};
use tracing::{warn};


#[derive(Debug, Clone)]
pub enum TargetSpec {
    Host(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub display: String, // 원래 입력(호스트/대역) 표시용
    pub ip: IpAddr,
}

pub fn load_targets(inline: &[String], path: Option<&Path>) -> Result<Vec<TargetSpec>> {
    let mut out = Vec::new();
    for s in inline {
        if s.trim().is_empty() { continue; }
        out.push(parse_spec(s));
    }
    if let Some(p) = path {
        let f = File::open(p).with_context(|| format!("open {:?}", p))?;
        for line in BufReader::new(f).lines().flatten() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') { continue; }
            out.push(parse_spec(l));
        }
    }
    Ok(out)
}

pub fn load_excludes(path: Option<&Path>) -> Result<Vec<IpNet>> {
    let mut out = Vec::new();
    if let Some(p) = path {
        let f = File::open(p).with_context(|| format!("open {:?}", p))?;
        for line in BufReader::new(f).lines().flatten() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') { continue; }
            if let Ok(net) = l.parse::<IpNet>() {
                out.push(net);
            } else if let Ok(ip) = l.parse::<IpAddr>() {
                out.push(match ip {
                    IpAddr::V4(v) => IpNet::V4(Ipv4Net::new(v, 32).unwrap()),
                    IpAddr::V6(v) => IpNet::V6(Ipv6Net::new(v, 128).unwrap()),
                });
            } else {
                warn!("exclude ignored: {}", l);
            }
        }
    }
    Ok(out)
}

fn parse_spec(s: &str) -> TargetSpec {
    if let Ok(ip) = s.parse::<IpAddr>() {
        TargetSpec::Ip(ip)
    } else if let Ok(net) = s.parse::<IpNet>() {
        TargetSpec::Cidr(net)
    } else {
        TargetSpec::Host(s.to_string())
    }
}

pub async fn resolve_all(
    specs: &[TargetSpec],
    excludes: &[IpNet],
    resolver: &TokioAsyncResolver,
    dns_timeout: Duration,
    seed: Option<u64>,
) -> Result<Vec<Resolved>> {
    let mut ips: Vec<Resolved> = Vec::new();

    for s in specs {
        match s {
            TargetSpec::Ip(ip) => {
                if !is_excluded(*ip, excludes) {
                    ips.push(Resolved { display: ip.to_string(), ip: *ip });
                }
            }
            TargetSpec::Cidr(net) => {
                for ip in expand(net) {
                    if !is_excluded(ip, excludes) {
                        ips.push(Resolved { display: net.to_string(), ip });
                    }
                }
            }
            TargetSpec::Host(name) => {
                match tokio::time::timeout(dns_timeout, resolver.lookup_ip(name.as_str())).await {
                    Ok(Ok(lookup)) => {
                        if let Some(ip) = lookup.iter().next() {
                            if !is_excluded(ip, excludes) {
                                ips.push(Resolved { display: name.clone(), ip });
                            }
                        } else {
                            warn!("dns empty: {}", name);
                        }
                    }
                    Ok(Err(e)) => warn!("dns error {}: {}", name, e),
                    Err(_) => warn!("dns timeout: {}", name),
                }
            }
        }
    }

    // 셔플(재현 가능한 시드)
    let mut rng = match seed {
        Some(s) => ChaCha8Rng::seed_from_u64(s),
        None => {
        let s: u64 = rand::random();
        ChaCha8Rng::seed_from_u64(s)
    }
    };
    ips.shuffle(&mut rng);
    Ok(ips)
}

fn expand(net: &IpNet) -> Vec<IpAddr> {
    match net {
        IpNet::V4(v4) => v4.hosts().map(IpAddr::V4).collect(),
        IpNet::V6(v6) => v6.hosts().take(1024).map(IpAddr::V6).collect(), // 과대역 보호
    }
}

fn is_excluded(ip: IpAddr, excludes: &[IpNet]) -> bool {
    excludes.iter().any(|n| n.contains(&ip))
}
