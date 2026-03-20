use colored::Colorize;
use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use serde_json::Value;

/// Output format requested by the user.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "table" => Some(OutputFormat::Table),
            "json" => Some(OutputFormat::Json),
            "csv" => Some(OutputFormat::Csv),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn render(results: &[Value], format: &OutputFormat, no_color: bool) {
    match format {
        OutputFormat::Json => render_json(results),
        OutputFormat::Csv => render_csv(results),
        OutputFormat::Table => render_table(results, no_color),
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn render_json(results: &[Value]) {
    println!("{}", serde_json::to_string_pretty(results).unwrap_or_default());
}

// ---------------------------------------------------------------------------
// CSV output — flat key=value per observable
// ---------------------------------------------------------------------------

fn render_csv(results: &[Value]) {
    let mut rows: Vec<std::collections::BTreeMap<String, String>> = Vec::new();
    let mut all_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for result in results {
        let row = flatten_result(result);
        all_keys.extend(row.keys().cloned());
        rows.push(row);
    }

    // Header
    let headers: Vec<&str> = all_keys.iter().map(|s| s.as_str()).collect();
    println!("{}", headers.join(";"));

    // Rows
    for row in &rows {
        let values: Vec<String> = all_keys
            .iter()
            .map(|k| row.get(k).cloned().unwrap_or_default())
            .map(|v| format!("\"{}\"", v.replace('"', "\"\"")))
            .collect();
        println!("{}", values.join(";"));
    }
}

/// Flatten a single result object into a string map (key → display value).
fn flatten_result(result: &Value) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();

    if let Some(obs) = result.get("observable").and_then(|v| v.as_str()) {
        map.insert("observable".into(), obs.to_string());
    }
    if let Some(t) = result.get("type").and_then(|v| v.as_str()) {
        map.insert("type".into(), t.to_string());
    }

    if let Some(obj) = result.as_object() {
        for (engine, data) in obj {
            if engine == "observable" || engine == "type" || engine == "reversed_success" {
                continue;
            }
            if let Some(inner) = data.as_object() {
                for (field, val) in inner {
                    let key = format!("{engine}_{field}");
                    map.insert(key, value_to_string(val));
                }
            }
        }
    }

    map
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        Value::Array(arr) => arr
            .iter()
            .map(value_to_string)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(_) => serde_json::to_string(v).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Table output
// ---------------------------------------------------------------------------

fn render_table(results: &[Value], no_color: bool) {
    for result in results {
        let observable = result
            .get("observable")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let obs_type = result
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        println!();
        if no_color {
            println!("Observable: {}  [{}]", observable, obs_type);
        } else {
            println!(
                "Observable: {}  [{}]",
                observable.bold().white(),
                obs_type.cyan()
            );
        }
        println!("{}", "─".repeat(72));

        let engine_results = collect_engine_rows(result);
        if engine_results.is_empty() {
            println!("  (no engine results)");
            continue;
        }

        let mut table = Table::new();
        table
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Engine").set_alignment(CellAlignment::Left),
                Cell::new("Result").set_alignment(CellAlignment::Left),
            ]);

        for (engine, summary, risk) in engine_results {
            let (engine_cell, summary_cell) = if no_color {
                (Cell::new(&engine), Cell::new(&summary))
            } else {
                let color = match risk {
                    RiskLevel::High => Color::Red,
                    RiskLevel::Medium => Color::Yellow,
                    RiskLevel::Low => Color::Green,
                    RiskLevel::Unknown => Color::White,
                };
                (
                    Cell::new(&engine).fg(Color::Cyan),
                    Cell::new(&summary).fg(color),
                )
            };
            table.add_row(vec![engine_cell, summary_cell]);
        }

        println!("{table}");
    }
}

#[derive(Debug, PartialEq)]
enum RiskLevel {
    High,
    Medium,
    Low,
    Unknown,
}

/// Extract a human-readable summary and risk level for each engine present.
fn collect_engine_rows(result: &Value) -> Vec<(String, String, RiskLevel)> {
    let skip = ["observable", "type", "reversed_success"];
    let obj = match result.as_object() {
        Some(o) => o,
        None => return vec![],
    };

    let mut rows = Vec::new();

    for (engine, data) in obj {
        if skip.contains(&engine.as_str()) || data.is_null() {
            continue;
        }

        let (summary, risk) = summarize_engine(engine, data);
        rows.push((engine.clone(), summary, risk));
    }

    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

fn summarize_engine(engine: &str, data: &Value) -> (String, RiskLevel) {
    match engine {
        "virustotal" => {
            let ratio = data
                .get("detection_ratio")
                .and_then(|v| v.as_str())
                .unwrap_or("?/?");
            let total: i64 = data
                .get("total_malicious")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let link = data.get("link").and_then(|v| v.as_str()).unwrap_or("");
            let risk = if total > 5 {
                RiskLevel::High
            } else if total > 0 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            (format!("Detection: {ratio}  malicious={total}  {link}"), risk)
        }

        "abuseipdb" => {
            let score: i64 = data
                .get("risk_score")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let reports: i64 = data
                .get("reports")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let country = data
                .get("country_code")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let isp = data.get("isp").and_then(|v| v.as_str()).unwrap_or("?");
            let risk = if score >= 75 {
                RiskLevel::High
            } else if score >= 25 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            (
                format!("Risk: {score}%  Reports: {reports}  Country: {country}  ISP: {isp}"),
                risk,
            )
        }

        "shodan" => {
            let ports = data
                .get("ports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.as_i64())
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            let link = data.get("link").and_then(|v| v.as_str()).unwrap_or("");
            (format!("Ports: [{ports}]  {link}"), RiskLevel::Unknown)
        }

        "bad_asn" => {
            let malicious = data
                .get("is_malicious")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let score: i64 = data
                .get("risk_score")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let asn = data.get("asn").and_then(|v| v.as_str()).unwrap_or("?");
            let sources = data
                .get("sources")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            let risk = if malicious {
                RiskLevel::High
            } else if score > 0 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            (
                format!("Malicious: {malicious}  Score: {score}  ASN: {asn}  Sources: {sources}"),
                risk,
            )
        }

        "google_dns" => {
            let a = data
                .get("A")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty());
            let mx = data
                .get("MX")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty());
            let mut parts = vec![];
            if let Some(a) = a { parts.push(format!("A: {a}")); }
            if let Some(mx) = mx { parts.push(format!("MX: {mx}")); }
            if parts.is_empty() { parts.push("(no records)".to_string()); }
            (parts.join("  "), RiskLevel::Unknown)
        }

        "rdap_whois" => {
            let registrar = data
                .get("registrar")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let created = data
                .get("creation_date")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let country = data
                .get("registrant_country")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            (
                format!("Registrar: {registrar}  Created: {created}  Country: {country}"),
                RiskLevel::Unknown,
            )
        }

        "reverse_dns" => {
            let records = data
                .get("reverse_dns")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            (format!("PTR: {records}"), RiskLevel::Unknown)
        }

        "urlscan" => {
            let link = data.get("link").and_then(|v| v.as_str()).unwrap_or("");
            let malicious = data
                .get("malicious")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let risk = if malicious { RiskLevel::High } else { RiskLevel::Low };
            (format!("Malicious: {malicious}  {link}"), risk)
        }

        "google_safe_browsing" => {
            let threats = data
                .get("threats")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "none".to_string());
            let risk = if threats != "none" && !threats.is_empty() {
                RiskLevel::High
            } else {
                RiskLevel::Low
            };
            (format!("Threats: {threats}"), risk)
        }

        "phishtank" => {
            let is_phish = data
                .get("is_phishing")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let risk = if is_phish { RiskLevel::High } else { RiskLevel::Low };
            (format!("Phishing: {is_phish}"), risk)
        }

        "ipapi" | "ipinfo" | "ipquery" => {
            let country = data
                .get("location")
                .and_then(|loc| loc.get("country"))
                .and_then(|v| v.as_str())
                .or_else(|| data.get("country_name").and_then(|v| v.as_str()))
                .unwrap_or("?");
            let asn = data
                .get("asn")
                .and_then(|asn| asn.get("asn"))
                .and_then(|v| v.as_str())
                .or_else(|| data.get("asn").and_then(|v| v.as_str()))
                .unwrap_or("?");
            let is_vpn = data
                .get("is_vpn")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_tor = data
                .get("is_tor")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let risk = if is_vpn || is_tor {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            (
                format!("Country: {country}  ASN: {asn}  VPN: {is_vpn}  Tor: {is_tor}"),
                risk,
            )
        }

        "chrome_extension" => {
            let name = data.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let url = data.get("url").and_then(|v| v.as_str()).unwrap_or("");
            (format!("Name: {name}  {url}"), RiskLevel::Unknown)
        }

        // Generic fallback: render key=value pairs for unknown engines
        _ => {
            let summary = if let Some(obj) = data.as_object() {
                obj.iter()
                    .take(5)
                    .map(|(k, v)| format!("{k}={}", value_to_string(v)))
                    .collect::<Vec<_>>()
                    .join("  ")
            } else {
                value_to_string(data)
            };
            (summary, RiskLevel::Unknown)
        }
    }
}
