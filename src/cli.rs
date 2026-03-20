use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "cyberbro",
    version,
    about = "CLI client for the Cyberbro threat intelligence server",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

// ---------------------------------------------------------------------------
// Top-level subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze one or more observables (IP, domain, hash, URL, email, …)
    Analyze(AnalyzeArgs),

    /// List and query the built-in engine registry
    #[command(subcommand)]
    Engines(EnginesCommand),
}

// ---------------------------------------------------------------------------
// analyze subcommand
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Observables to analyze (IP, FQDN, hash, URL, email, …).
    /// Multiple values can be separated by spaces.
    #[arg(required_unless_present = "file")]
    pub observables: Vec<String>,

    /// Read observables from a file (one per line, # lines ignored).
    #[arg(short, long, value_name = "PATH")]
    pub file: Option<std::path::PathBuf>,

    /// Override auto-detected observable type for all inputs.
    /// Accepted values: IPv4, IPv6, FQDN, URL, MD5, SHA1, SHA256, Email,
    /// CHROME_EXTENSION, BOGON
    #[arg(long, value_name = "TYPE")]
    pub r#type: Option<String>,

    /// Comma-separated list of engines to use (e.g. virustotal,shodan).
    #[arg(short, long, value_delimiter = ',')]
    pub engines: Vec<String>,

    /// Use all engines compatible with the detected observable type.
    #[arg(long)]
    pub all_engines: bool,

    /// Comma-separated engines to exclude (useful with --all-engines).
    #[arg(long, value_delimiter = ',', value_name = "ENGINE,...")]
    pub exclude: Vec<String>,

    /// Output format: table (default), json, csv
    #[arg(short, long, default_value = "table", value_name = "FORMAT")]
    pub output: String,

    /// Bypass server-side cache and force a fresh analysis.
    #[arg(long)]
    pub ignore_cache: bool,

    /// Maximum seconds to wait for analysis to complete.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Seconds between completion status polls.
    #[arg(long, value_name = "SECS")]
    pub poll_interval: Option<u64>,

    /// Suppress progress output (spinner, status messages).
    #[arg(short, long)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,

    // ----- Connection flags (override config) -----

    /// Cyberbro server base URL (e.g. http://localhost:5000).
    #[arg(long, value_name = "URL", env = "CYBERBRO_SERVER")]
    pub server: Option<String>,

    /// API path prefix (default: api).
    #[arg(long, value_name = "PREFIX", env = "CYBERBRO_API_PREFIX")]
    pub api_prefix: Option<String>,

    /// Disable TLS certificate verification (insecure).
    #[arg(long)]
    pub no_tls_verify: bool,
}

// ---------------------------------------------------------------------------
// engines subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum EnginesCommand {
    /// List all known engines (optionally filtered by observable type).
    List(EnginesListArgs),

    /// Show details for a specific engine.
    Show(EnginesShowArgs),
}

#[derive(Args, Debug)]
pub struct EnginesListArgs {
    /// Filter engines by observable type (e.g. IPv4, FQDN, SHA256).
    #[arg(long, value_name = "TYPE")]
    pub r#type: Option<String>,

    /// Show only engines that do NOT require an API key.
    #[arg(long)]
    pub free_only: bool,
}

#[derive(Args, Debug)]
pub struct EnginesShowArgs {
    /// Engine name (e.g. virustotal).
    pub name: String,
}
