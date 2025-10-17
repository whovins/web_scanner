// src/scanner/vuln_db.rs
use anyhow::{Result, Context};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnRule {
    pub pattern: String,     // regex string
    pub field: String,       // "service" | "title" | "header" (for future)
    pub level: String,       // "info"|"warning"|"critical"
    pub message: String,
    pub confidence: f32,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub fn load_rules_from_file(path: &str) -> Result<Vec<VulnRule>> {
    let contents = fs::read_to_string(path).context("failed to read vuln db file")?;
    let rules: Vec<VulnRule> = serde_json::from_str(&contents).context("failed to parse vuln db json")?;
    Ok(rules)
}

pub fn default_rules() -> Vec<VulnRule> {
    // a small helpful default set
    vec![
        VulnRule {
            pattern: r"(?i)apache/2\.4\.7".to_string(),
            field: "service".to_string(),
            level: "warning".to_string(),
            message: "Apache 2.4.7 is EOL / historically vulnerable - verify patch level".to_string(),
            confidence: 0.8,
            tags: vec!["apache".to_string()],
        },
        VulnRule {
            pattern: r"(?i)nginx/1\.14".to_string(),
            field: "service".to_string(),
            level: "info".to_string(),
            message: "nginx 1.14 series may be outdated - check CVEs".to_string(),
            confidence: 0.5,
            tags: vec!["nginx".to_string()],
        },
        VulnRule {
            pattern: r"(?i)php/5\.".to_string(),
            field: "service".to_string(),
            level: "warning".to_string(),
            message: "PHP 5.x detected — end-of-life and multiple vulnerabilities".to_string(),
            confidence: 0.95,
            tags: vec!["php".to_string()],
        },
        // detect Juice Shop by title (useful for tests)
        VulnRule {
            pattern: r"(?i)juice shop".to_string(),
            field: "title".to_string(),
            level: "info".to_string(),
            message: "OWASP Juice Shop (intentionally insecure test app)".to_string(),
            confidence: 0.6,
            tags: vec!["testapp".to_string()],
        },
    ]
}

pub fn match_vulns(field_value: Option<&str>, rules: &Vec<VulnRule>, field_name: &str) -> Vec<crate::scanner::http::Warning> {
    let mut out = Vec::new();
    if field_value.is_none() { return out; }
    let val = field_value.unwrap();
    for r in rules.iter().filter(|r| r.field.eq_ignore_ascii_case(field_name)) {
        if let Ok(re) = Regex::new(&r.pattern) {
            if re.is_match(val) {
                out.push(crate::scanner::http::Warning {
                    level: r.level.clone(),
                    message: format!("{} (matched rule: {})", r.message, r.pattern),
                    confidence: r.confidence,
                });
            }
        }
    }
    out
}
