use crate::input::ObservableType;

/// Static metadata about a single Cyberbro engine.
#[derive(Debug, Clone)]
pub struct EngineInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub supported_types: &'static [&'static str], // ObservableType::as_str() values
    pub requires_api_key: bool,
}

impl EngineInfo {
    /// Returns true if this engine supports the given observable type.
    pub fn supports(&self, obs_type: &ObservableType) -> bool {
        self.supported_types.contains(&obs_type.as_str())
    }
}

/// All 33 engines known to Cyberbro, with their supported observable types.
pub const ALL_ENGINES: &[EngineInfo] = &[
    EngineInfo {
        name: "abuseipdb",
        description: "AbuseIPDB — IP abuse reports and confidence score",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "abusix",
        description: "Abusix — Abuse contact lookup for IPs",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "alienvault",
        description: "AlienVault OTX — Threat intelligence and IOC data",
        supported_types: &["IPv4", "IPv6", "FQDN", "URL", "MD5", "SHA1", "SHA256"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "bad_asn",
        description: "Bad ASN — Spamhaus ASNDROP, Brianhama, VPN/proxy detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "chrome_extension",
        description: "Chrome Extension — Fetch extension name from Chrome/Edge store",
        supported_types: &["CHROME_EXTENSION"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "criminalip",
        description: "CriminalIP — IP reputation and abuse detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "crowdstrike",
        description: "CrowdStrike Falcon — EDR and threat intelligence lookup",
        supported_types: &["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "crtsh",
        description: "crt.sh — TLS certificate subdomain enumeration",
        supported_types: &["FQDN", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "dfir_iris",
        description: "DFIR IRIS — Case search in DFIR platform",
        supported_types: &["BOGON", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "github",
        description: "GitHub / grep.app — Code search across public repositories",
        supported_types: &[
            "Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL",
            "CHROME_EXTENSION",
        ],
        requires_api_key: false,
    },
    EngineInfo {
        name: "google",
        description: "Google Custom Search — Web search for observable",
        supported_types: &[
            "Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL",
            "CHROME_EXTENSION",
        ],
        requires_api_key: true,
    },
    EngineInfo {
        name: "google_dns",
        description: "Google DNS — DNS record lookup (A, MX, TXT, SPF, DMARC, PTR, etc.)",
        supported_types: &["FQDN", "IPv4", "IPv6", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "google_safe_browsing",
        description: "Google Safe Browsing — Malware and phishing detection",
        supported_types: &["FQDN", "IPv4", "IPv6", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "hudsonrock",
        description: "Hudson Rock — Breach and credential data search",
        supported_types: &["Email", "FQDN", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "ioc_one_html",
        description: "IoC.One HTML — IoC.One scraping (may be slow)",
        supported_types: &[
            "Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL",
            "CHROME_EXTENSION",
        ],
        requires_api_key: false,
    },
    EngineInfo {
        name: "ioc_one_pdf",
        description: "IoC.One PDF — IoC.One PDF report scraping (may be slow)",
        supported_types: &[
            "Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL",
            "CHROME_EXTENSION",
        ],
        requires_api_key: false,
    },
    EngineInfo {
        name: "ipapi",
        description: "ipapi — IP geolocation, ASN, VPN/proxy/Tor detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "ipinfo",
        description: "IPinfo — IP geolocation, ASN, privacy detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "ipquery",
        description: "IPquery — IP geolocation, ASN, VPN/proxy detection (no key needed)",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "mde",
        description: "Microsoft Defender for Endpoint — Enterprise EDR lookup",
        supported_types: &["BOGON", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "misp",
        description: "MISP — Search your MISP threat intelligence instance",
        supported_types: &["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "opencti",
        description: "OpenCTI — Search your OpenCTI platform",
        supported_types: &[
            "Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL",
            "CHROME_EXTENSION",
        ],
        requires_api_key: true,
    },
    EngineInfo {
        name: "phishtank",
        description: "PhishTank — Phishing site detection",
        supported_types: &["FQDN", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "rdap_whois",
        description: "RDAP/Whois — Domain registration data and abuse contacts",
        supported_types: &["FQDN", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "reverse_dns",
        description: "Reverse DNS — DNS resolution pivot (modifies observable type)",
        supported_types: &["BOGON", "FQDN", "IPv4", "IPv6", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "rl_analyze",
        description: "Reversing Labs Spectra Analyze — File reputation and analysis",
        supported_types: &["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "rosti",
        description: "Rösti — Repackaged Open Source Threat Intelligence",
        supported_types: &["Email", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "shodan",
        description: "Shodan — Port/service scanning results for IPs",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "spur",
        description: "Spur.us — VPN/proxy/anonymization detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "threatfox",
        description: "ThreatFox (Abuse.ch) — Threat indicator database",
        supported_types: &["FQDN", "IPv4", "IPv6", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "urlscan",
        description: "urlscan.io — URL scanning and webpage analysis",
        supported_types: &["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: false,
    },
    EngineInfo {
        name: "virustotal",
        description: "VirusTotal — Multi-AV detection ratios and community scores",
        supported_types: &["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"],
        requires_api_key: true,
    },
    EngineInfo {
        name: "webscout",
        description: "WebScout — Web scanning and hosting detection",
        supported_types: &["IPv4", "IPv6"],
        requires_api_key: true,
    },
];

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// Find an engine by name (case-insensitive).
pub fn find_engine(name: &str) -> Option<&'static EngineInfo> {
    ALL_ENGINES.iter().find(|e| e.name.eq_ignore_ascii_case(name))
}

/// Return all engines compatible with the given observable type.
pub fn engines_for_type(obs_type: &ObservableType) -> Vec<&'static EngineInfo> {
    ALL_ENGINES.iter().filter(|e| e.supports(obs_type)).collect()
}

/// Validate a list of engine names; return the unknown ones.
pub fn unknown_engines<'a>(names: &'a [String]) -> Vec<&'a str> {
    names
        .iter()
        .filter(|n| find_engine(n).is_none())
        .map(|n| n.as_str())
        .collect()
}

/// Resolve the final engine list given user flags.
///
/// - If `selected` is non-empty, use those (warn on unsupported types).
/// - If `all_engines`, use every compatible engine minus `excluded`.
/// - Otherwise fall back to a sensible default for the observable type.
pub fn resolve_engines(
    obs_type: &ObservableType,
    selected: &[String],
    excluded: &[String],
    all_engines: bool,
) -> Vec<String> {
    let excluded_lower: Vec<String> = excluded.iter().map(|s| s.to_lowercase()).collect();

    let base: Vec<&'static EngineInfo> = if !selected.is_empty() {
        selected
            .iter()
            .filter_map(|n| find_engine(n))
            .collect()
    } else if all_engines {
        engines_for_type(obs_type)
    } else {
        default_engines(obs_type)
    };

    base.into_iter()
        .filter(|e| !excluded_lower.contains(&e.name.to_lowercase()))
        .map(|e| e.name.to_string())
        .collect()
}

/// Sensible defaults per observable type (no API key required where possible).
fn default_engines(obs_type: &ObservableType) -> Vec<&'static EngineInfo> {
    let defaults: &[&str] = match obs_type {
        ObservableType::IPv4 | ObservableType::IPv6 => &[
            "abuseipdb", "virustotal", "shodan", "ipquery", "google_dns", "reverse_dns",
            "bad_asn", "urlscan",
        ],
        ObservableType::Fqdn => &[
            "virustotal", "urlscan", "google_dns", "rdap_whois", "crtsh", "phishtank",
            "google_safe_browsing",
        ],
        ObservableType::Url => &[
            "virustotal", "urlscan", "phishtank", "google_safe_browsing", "google_dns",
        ],
        ObservableType::Md5 | ObservableType::Sha1 | ObservableType::Sha256 => {
            &["virustotal", "urlscan", "alienvault"]
        }
        ObservableType::Email => &["hudsonrock", "github", "google"],
        ObservableType::ChromeExtension => &["chrome_extension", "github", "opencti"],
        ObservableType::Bogon => &["reverse_dns", "mde", "dfir_iris"],
    };

    defaults
        .iter()
        .filter_map(|n| find_engine(n))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::ObservableType;

    #[test]
    fn test_all_engines_have_unique_names() {
        let mut names = std::collections::HashSet::new();
        for e in ALL_ENGINES {
            assert!(names.insert(e.name), "Duplicate engine name: {}", e.name);
        }
    }

    #[test]
    fn test_find_engine() {
        assert!(find_engine("virustotal").is_some());
        assert!(find_engine("VIRUSTOTAL").is_some());
        assert!(find_engine("nonexistent").is_none());
    }

    #[test]
    fn test_engines_for_ipv4() {
        let engines = engines_for_type(&ObservableType::IPv4);
        let names: Vec<&str> = engines.iter().map(|e| e.name).collect();
        assert!(names.contains(&"abuseipdb"));
        assert!(names.contains(&"shodan"));
        assert!(names.contains(&"virustotal"));
        assert!(!names.contains(&"rdap_whois")); // rdap_whois only supports FQDN/URL
    }

    #[test]
    fn test_unknown_engines() {
        let names = vec!["virustotal".to_string(), "bogus_engine".to_string()];
        let unknown = unknown_engines(&names);
        assert_eq!(unknown, vec!["bogus_engine"]);
    }

    #[test]
    fn test_engine_count() {
        assert_eq!(ALL_ENGINES.len(), 33);
    }
}
