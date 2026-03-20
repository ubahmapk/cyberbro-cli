use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{CyberbroError, Result};

/// Resolved configuration (merged from file → env vars → CLI flags).
#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub api_prefix: String,
    pub default_engines: Vec<String>,
    pub timeout_secs: u64,
    pub poll_interval_secs: u64,
    pub verify_tls: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "http://localhost:5000".into(),
            api_prefix: "api".into(),
            default_engines: vec![],
            timeout_secs: 120,
            poll_interval_secs: 2,
            verify_tls: true,
        }
    }
}

/// Raw config file format (`~/.config/cyberbro-cli/config.toml`).
#[derive(Debug, Deserialize, Serialize, Default)]
struct ConfigFile {
    server: Option<String>,
    api_prefix: Option<String>,
    default_engines: Option<Vec<String>>,
    timeout: Option<u64>,
    poll_interval: Option<u64>,
    verify_tls: Option<bool>,
}

impl Config {
    /// Load configuration in priority order:
    /// defaults → config file → environment variables.
    /// CLI flags are applied later by the caller via `apply_cli_overrides`.
    pub fn load() -> Result<Self> {
        let mut cfg = Self::default();

        if let Some(file_cfg) = load_config_file()? {
            if let Some(s) = file_cfg.server { cfg.server = s; }
            if let Some(p) = file_cfg.api_prefix { cfg.api_prefix = p; }
            if let Some(e) = file_cfg.default_engines { cfg.default_engines = e; }
            if let Some(t) = file_cfg.timeout { cfg.timeout_secs = t; }
            if let Some(p) = file_cfg.poll_interval { cfg.poll_interval_secs = p; }
            if let Some(v) = file_cfg.verify_tls { cfg.verify_tls = v; }
        }

        // Environment variable overrides
        if let Ok(s) = std::env::var("CYBERBRO_SERVER") {
            cfg.server = s;
        }
        if let Ok(p) = std::env::var("CYBERBRO_API_PREFIX") {
            cfg.api_prefix = p;
        }
        if let Ok(t) = std::env::var("CYBERBRO_TIMEOUT") {
            cfg.timeout_secs = t.parse().map_err(|_| {
                CyberbroError::ConfigError(
                    "CYBERBRO_TIMEOUT must be a positive integer".into(),
                )
            })?;
        }

        Ok(cfg)
    }

    /// Apply CLI flag overrides (highest priority).
    pub fn apply_cli_overrides(
        &mut self,
        server: Option<&str>,
        api_prefix: Option<&str>,
        timeout: Option<u64>,
        poll_interval: Option<u64>,
        no_tls_verify: bool,
    ) {
        if let Some(s) = server { self.server = s.to_string(); }
        if let Some(p) = api_prefix { self.api_prefix = p.to_string(); }
        if let Some(t) = timeout { self.timeout_secs = t; }
        if let Some(p) = poll_interval { self.poll_interval_secs = p; }
        if no_tls_verify { self.verify_tls = false; }
    }
}

fn config_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("cyberbro-cli").join("config.toml"))
}

fn load_config_file() -> Result<Option<ConfigFile>> {
    let path = match config_file_path() {
        Some(p) => p,
        None => return Ok(None),
    };

    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&path)?;
    let cfg: ConfigFile = toml::from_str(&content).map_err(|e| {
        CyberbroError::ConfigError(format!(
            "Failed to parse config file {}: {e}",
            path.display()
        ))
    })?;

    Ok(Some(cfg))
}
