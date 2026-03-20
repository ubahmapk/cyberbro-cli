use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::{CyberbroError, Result};

/// Observable types matching the Cyberbro server's classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservableType {
    IPv4,
    IPv6,
    Fqdn,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    ChromeExtension,
    Bogon,
}

impl ObservableType {
    /// Server-side string representation used in API requests/responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObservableType::IPv4 => "IPv4",
            ObservableType::IPv6 => "IPv6",
            ObservableType::Fqdn => "FQDN",
            ObservableType::Url => "URL",
            ObservableType::Md5 => "MD5",
            ObservableType::Sha1 => "SHA1",
            ObservableType::Sha256 => "SHA256",
            ObservableType::Email => "Email",
            ObservableType::ChromeExtension => "CHROME_EXTENSION",
            ObservableType::Bogon => "BOGON",
        }
    }

    /// Parse from server-side string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "IPv4" => Some(ObservableType::IPv4),
            "IPv6" => Some(ObservableType::IPv6),
            "FQDN" => Some(ObservableType::Fqdn),
            "URL" => Some(ObservableType::Url),
            "MD5" => Some(ObservableType::Md5),
            "SHA1" => Some(ObservableType::Sha1),
            "SHA256" => Some(ObservableType::Sha256),
            "Email" => Some(ObservableType::Email),
            "CHROME_EXTENSION" => Some(ObservableType::ChromeExtension),
            "BOGON" => Some(ObservableType::Bogon),
            _ => None,
        }
    }

    /// All user-facing type names accepted by --type flag.
    pub fn parse_flag(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "IPV4" => Some(ObservableType::IPv4),
            "IPV6" => Some(ObservableType::IPv6),
            "FQDN" | "DOMAIN" => Some(ObservableType::Fqdn),
            "URL" => Some(ObservableType::Url),
            "MD5" => Some(ObservableType::Md5),
            "SHA1" => Some(ObservableType::Sha1),
            "SHA256" => Some(ObservableType::Sha256),
            "EMAIL" => Some(ObservableType::Email),
            "CHROME_EXTENSION" | "CHROME" => Some(ObservableType::ChromeExtension),
            "BOGON" => Some(ObservableType::Bogon),
            _ => None,
        }
    }
}

impl std::fmt::Display for ObservableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A classified, defanged observable ready for submission.
#[derive(Debug, Clone)]
pub struct Observable {
    /// Original user input (possibly fanged).
    pub raw: String,
    /// Defanged/normalized value sent to the server.
    pub value: String,
    pub obs_type: ObservableType,
}

// ---------------------------------------------------------------------------
// Regex patterns (compiled once)
// ---------------------------------------------------------------------------

static RE_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(https?|ftp)://[^\s]+$").unwrap()
});

static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$").unwrap()
});

// Simplified but comprehensive IPv6 pattern
static RE_IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    ).unwrap()
});

static RE_SHA256: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{64}$").unwrap()
});

static RE_SHA1: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{40}$").unwrap()
});

static RE_MD5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{32}$").unwrap()
});

static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$").unwrap()
});

// Chrome extension IDs: exactly 32 lowercase letters
static RE_CHROME_EXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z]{32}$").unwrap()
});

// FQDN: at least two labels separated by dots, valid TLD
static RE_FQDN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$").unwrap()
});

// ---------------------------------------------------------------------------
// Bogon / private IP ranges (RFC 1918, RFC 5735, etc.)
// ---------------------------------------------------------------------------

fn is_bogon_ipv4(a: u8, b: u8, c: u8, d: u8) -> bool {
    matches!(
        (a, b, c, d),
        (0, _, _, _)           // 0.0.0.0/8
        | (10, _, _, _)        // 10.0.0.0/8
        | (100, 64..=127, _, _) // 100.64.0.0/10 (CGNAT)
        | (127, _, _, _)       // 127.0.0.0/8 loopback
        | (169, 254, _, _)     // 169.254.0.0/16 link-local
        | (172, 16..=31, _, _) // 172.16.0.0/12
        | (192, 0, 0, _)       // 192.0.0.0/24
        | (192, 0, 2, _)       // 192.0.2.0/24 TEST-NET-1
        | (192, 168, _, _)     // 192.168.0.0/16
        | (198, 18..=19, _, _) // 198.18.0.0/15 benchmarking
        | (198, 51, 100, _)    // 198.51.100.0/24 TEST-NET-2
        | (203, 0, 113, _)     // 203.0.113.0/24 TEST-NET-3
        | (224..=239, _, _, _) // 224.0.0.0/4 multicast
        | (240..=254, _, _, _) // 240.0.0.0/4 reserved
        | (255, 255, 255, 255) // broadcast
    )
}

// ---------------------------------------------------------------------------
// Defanging
// ---------------------------------------------------------------------------

/// Restore a fanged observable to its original form.
/// Handles common defanging patterns used in threat intel reports.
pub fn defang(input: &str) -> String {
    let s = input.trim().to_string();
    // hxxp/hxxps -> http/https
    let s = s.replace("hxxps://", "https://")
              .replace("hxxp://", "http://")
              .replace("hXXps://", "https://")
              .replace("hXXp://", "http://");
    // [.] or (.) -> .
    let s = s.replace("[.]", ".").replace("(.)",".");
    // [:]  -> :
    let s = s.replace("[:]", ":");
    // [at] -> @
    let s = s.replace("[at]", "@").replace("[@]", "@");
    // remove surrounding brackets if present
    s.trim_matches(|c| c == '[' || c == ']').to_string()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect the type of a (possibly fanged) observable and return a validated
/// [`Observable`]. Returns an error if the value cannot be classified.
pub fn detect(raw: &str) -> Result<Observable> {
    let value = defang(raw);
    let obs_type = classify(&value).ok_or_else(|| CyberbroError::ValidationError {
        input: raw.to_string(),
        reason: "could not determine observable type (IPv4/IPv6/FQDN/URL/hash/email)".to_string(),
    })?;
    Ok(Observable {
        raw: raw.to_string(),
        value,
        obs_type,
    })
}

/// Classify an already-defanged string. Returns `None` if unrecognised.
pub fn classify(value: &str) -> Option<ObservableType> {
    // URL must be tested before FQDN (URLs contain FQDNs)
    if RE_URL.is_match(value) {
        return Some(ObservableType::Url);
    }

    // IPv4 before FQDN (digits-only labels would match FQDN otherwise)
    if let Some(caps) = RE_IPV4.captures(value) {
        let octets: Vec<u8> = (1..=4)
            .filter_map(|i| caps.get(i)?.as_str().parse::<u8>().ok())
            .collect();
        if octets.len() == 4 {
            let (a, b, c, d) = (octets[0], octets[1], octets[2], octets[3]);
            if is_bogon_ipv4(a, b, c, d) {
                return Some(ObservableType::Bogon);
            }
            return Some(ObservableType::IPv4);
        }
    }

    if RE_IPV6.is_match(value) {
        return Some(ObservableType::IPv6);
    }

    // Chrome extension IDs: exactly 32 lowercase a-z letters (no digits/uppercase).
    // Must be checked before MD5 (which also has 32 chars but uses [a-fA-F0-9]).
    if RE_CHROME_EXT.is_match(value) {
        return Some(ObservableType::ChromeExtension);
    }

    // Hashes (longest first to avoid SHA1/MD5 false positives on SHA256)
    if RE_SHA256.is_match(value) {
        return Some(ObservableType::Sha256);
    }
    if RE_SHA1.is_match(value) {
        return Some(ObservableType::Sha1);
    }
    if RE_MD5.is_match(value) {
        return Some(ObservableType::Md5);
    }

    if RE_EMAIL.is_match(value) {
        return Some(ObservableType::Email);
    }

    if RE_FQDN.is_match(value) {
        return Some(ObservableType::Fqdn);
    }

    None
}

/// Parse multiple observables from a newline/comma/space separated string.
pub fn parse_list(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == '\n' || c == ',' || c == '\r')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        assert_eq!(classify("8.8.8.8"), Some(ObservableType::IPv4));
        assert_eq!(classify("1.1.1.1"), Some(ObservableType::IPv4));
        assert_eq!(classify("255.255.255.0"), Some(ObservableType::IPv4));
    }

    #[test]
    fn test_bogon() {
        assert_eq!(classify("127.0.0.1"), Some(ObservableType::Bogon));
        assert_eq!(classify("192.168.1.1"), Some(ObservableType::Bogon));
        assert_eq!(classify("10.0.0.1"), Some(ObservableType::Bogon));
        assert_eq!(classify("172.16.0.1"), Some(ObservableType::Bogon));
    }

    #[test]
    fn test_ipv6() {
        assert_eq!(classify("2001:db8::1"), Some(ObservableType::IPv6));
        assert_eq!(classify("::1"), Some(ObservableType::IPv6));
        assert_eq!(
            classify("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some(ObservableType::IPv6)
        );
    }

    #[test]
    fn test_hashes() {
        assert_eq!(
            classify("d41d8cd98f00b204e9800998ecf8427e"),
            Some(ObservableType::Md5)
        );
        assert_eq!(
            classify("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some(ObservableType::Sha1)
        );
        assert_eq!(
            classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(ObservableType::Sha256)
        );
    }

    #[test]
    fn test_url() {
        assert_eq!(
            classify("https://example.com/path?q=1"),
            Some(ObservableType::Url)
        );
        assert_eq!(classify("http://malware.site"), Some(ObservableType::Url));
        assert_eq!(
            classify("ftp://files.example.com/file.txt"),
            Some(ObservableType::Url)
        );
    }

    #[test]
    fn test_fqdn() {
        assert_eq!(classify("example.com"), Some(ObservableType::Fqdn));
        assert_eq!(classify("sub.domain.co.uk"), Some(ObservableType::Fqdn));
    }

    #[test]
    fn test_email() {
        assert_eq!(
            classify("user@example.com"),
            Some(ObservableType::Email)
        );
    }

    #[test]
    fn test_chrome_extension() {
        // 32 lowercase letters
        assert_eq!(
            classify("abcdefghijklmnopqrstuvwxyzabcdef"),
            Some(ObservableType::ChromeExtension)
        );
    }

    #[test]
    fn test_defang() {
        assert_eq!(defang("hxxps://example[.]com"), "https://example.com");
        assert_eq!(defang("8.8.8[.]8"), "8.8.8.8");
        assert_eq!(defang("user[at]example.com"), "user@example.com");
    }

    #[test]
    fn test_detect_fanged() {
        let obs = detect("hxxps://malware[.]site/path").unwrap();
        assert_eq!(obs.obs_type, ObservableType::Url);
        assert_eq!(obs.value, "https://malware.site/path");
    }

    #[test]
    fn test_parse_list() {
        let list = parse_list("8.8.8.8\nexample.com\n# comment\n1.1.1.1");
        assert_eq!(list, vec!["8.8.8.8", "example.com", "1.1.1.1"]);
    }
}
