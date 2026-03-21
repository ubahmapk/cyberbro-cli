mod cli;
mod client;
mod config;
mod engines;
mod error;
mod input;
mod results;

use clap::Parser;
use colored::Colorize;
use comfy_table::{Cell, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Command, ConfigArgs, ConfigSubcommand, EnginesCommand};
use config::Config;
use engines::{find_engine, resolve_engines, unknown_engines, ALL_ENGINES};
use error::CyberbroError;
use input::{detect, parse_list, ObservableType};
use results::{render, OutputFormat};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("{} {e}", "error:".red().bold());
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> error::Result<()> {
    match cli.command {
        Command::Engines(sub) => run_engines(sub),
        Command::Config(sub) => run_config(sub),
        Command::Analyze(args) => run_analyze(args).await,
    }
}

// ---------------------------------------------------------------------------
// engines subcommand
// ---------------------------------------------------------------------------

fn run_engines(cmd: EnginesCommand) -> error::Result<()> {
    match cmd {
        EnginesCommand::List(args) => {
            // Optional type filter
            let type_filter: Option<ObservableType> = args
                .r#type
                .as_deref()
                .map(|t| {
                    ObservableType::parse_flag(t).ok_or_else(|| CyberbroError::ValidationError {
                        input: t.to_string(),
                        reason: format!(
                            "unknown type '{t}'. Valid types: IPv4, IPv6, FQDN, URL, MD5, SHA1, SHA256, Email, CHROME_EXTENSION, BOGON"
                        ),
                    })
                })
                .transpose()?;

            let filtered: Vec<_> = ALL_ENGINES
                .iter()
                .filter(|e| {
                    if let Some(ref t) = type_filter {
                        if !e.supports(t) {
                            return false;
                        }
                    }
                    if args.free_only && e.requires_api_key {
                        return false;
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                println!("No engines match the given filters.");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["Engine", "API Key?", "Supported Types", "Description"]);

            for e in filtered {
                table.add_row(vec![
                    Cell::new(e.name).fg(comfy_table::Color::Cyan),
                    Cell::new(if e.requires_api_key { "yes" } else { "no" }),
                    Cell::new(e.supported_types.join(", ")),
                    Cell::new(e.description),
                ]);
            }

            println!("{table}");
        }

        EnginesCommand::Show(args) => {
            let engine = find_engine(&args.name).ok_or_else(|| CyberbroError::UnknownEngine(args.name.clone()))?;

            println!();
            println!("  Name:         {}", engine.name.bold().cyan());
            println!("  Description:  {}", engine.description);
            println!("  API Key:      {}", if engine.requires_api_key { "required".yellow().to_string() } else { "not required".green().to_string() });
            println!("  Supports:     {}", engine.supported_types.join(", "));
            println!();
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// config subcommand
// ---------------------------------------------------------------------------

fn run_config(args: ConfigArgs) -> error::Result<()> {
    match args.command {
        Some(ConfigSubcommand::Init(init_args)) => run_config_init(init_args),
        Some(ConfigSubcommand::Show) | None => run_config_show(),
    }
}

fn run_config_show() -> error::Result<()> {
    let cfg = Config::load()?;
    let path = config::config_file_path();

    println!();
    println!(
        "  Config file:      {}",
        match &path {
            Some(p) if p.exists() => p.display().to_string().green().to_string(),
            Some(p) => format!("{} (not found — using defaults)", p.display())
                .yellow()
                .to_string(),
            None => "(cannot determine path)".yellow().to_string(),
        }
    );
    println!("  server:           {}", cfg.server);
    println!("  api_prefix:       {}", cfg.api_prefix);
    println!("  timeout:          {}s", cfg.timeout_secs);
    println!("  poll_interval:    {}s", cfg.poll_interval_secs);
    println!("  verify_tls:       {}", cfg.verify_tls);
    let engines = if cfg.default_engines.is_empty() {
        "(none — use server defaults)".dimmed().to_string()
    } else {
        cfg.default_engines.join(", ")
    };
    println!("  default_engines:  {}", engines);
    println!();

    Ok(())
}

fn run_config_init(args: cli::InitArgs) -> error::Result<()> {
    use config::ConfigFile;
    use dialoguer::{Confirm, Input};

    // Check for an existing config file and refuse unless --force.
    if let Some(path) = config::config_file_path() {
        if path.exists() && !args.force {
            println!(
                "Config file already exists at {}",
                path.display()
            );
            println!("Use --force to overwrite it.");
            return Ok(());
        }
    }

    // Build a ConfigFile, either from defaults or by prompting the user.
    let cfg = if args.defaults {
        // Non-interactive: use compile-time defaults directly.
        ConfigFile {
            server: Some("http://localhost:5000".into()),
            api_prefix: Some("api".into()),
            timeout: Some(120),
            poll_interval: Some(2),
            verify_tls: Some(true),
            default_engines: Some(vec![]),
        }
    } else {
        // Interactive: prompt for each value, showing the default.
        // dialoguer handles the case where stdout is not a TTY by
        // returning the default value automatically.

        let server: String = Input::new()
            .with_prompt("Cyberbro server URL")
            .default("http://localhost:5000".into())
            .interact_text()?;

        let api_prefix: String = Input::new()
            .with_prompt("API path prefix")
            .default("api".into())
            .interact_text()?;

        let timeout: u64 = Input::new()
            .with_prompt("Request timeout (seconds)")
            .default(120)
            .interact_text()?;

        let poll_interval: u64 = Input::new()
            .with_prompt("Polling interval (seconds)")
            .default(2)
            .interact_text()?;

        let verify_tls: bool = Confirm::new()
            .with_prompt("Verify TLS certificates?")
            .default(true)
            .interact()?;

        let engines_raw: String = Input::new()
            .with_prompt("Default engines, comma-separated (blank for none)")
            .default(String::new())
            .allow_empty(true)
            .interact_text()?;

        let default_engines: Vec<String> = if engines_raw.trim().is_empty() {
            vec![]
        } else {
            engines_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        ConfigFile {
            server: Some(server),
            api_prefix: Some(api_prefix),
            timeout: Some(timeout),
            poll_interval: Some(poll_interval),
            verify_tls: Some(verify_tls),
            default_engines: Some(default_engines),
        }
    };

    let path = config::write_config_file(&cfg)?;
    println!("Config written to {}", path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// analyze subcommand
// ---------------------------------------------------------------------------

async fn run_analyze(args: cli::AnalyzeArgs) -> error::Result<()> {
    // --- Load and merge config ---
    let mut cfg = Config::load()?;
    cfg.apply_cli_overrides(
        args.server.as_deref(),
        args.api_prefix.as_deref(),
        args.timeout,
        args.poll_interval,
        args.no_tls_verify,
    );

    // --- Collect observables ---
    let mut raw_inputs: Vec<String> = args.observables.clone();

    if let Some(path) = &args.file {
        let content = std::fs::read_to_string(path)?;
        raw_inputs.extend(parse_list(&content));
    }

    if raw_inputs.is_empty() {
        return Err(CyberbroError::ValidationError {
            input: String::new(),
            reason: "no observables provided (use positional args or --file)".into(),
        });
    }

    // --- Validate output format ---
    let fmt = OutputFormat::from_str(&args.output).ok_or_else(|| {
        CyberbroError::ValidationError {
            input: args.output.clone(),
            reason: "output format must be one of: table, json, csv".into(),
        }
    })?;

    // --- Detect & validate each observable ---
    let mut observables = Vec::new();
    for raw in &raw_inputs {
        let obs = if let Some(forced_type) = args.r#type.as_deref() {
            let t = ObservableType::parse_flag(forced_type).ok_or_else(|| {
                CyberbroError::ValidationError {
                    input: forced_type.to_string(),
                    reason: "unknown --type value".into(),
                }
            })?;
            input::Observable {
                raw: raw.clone(),
                value: input::defang(raw),
                obs_type: t,
            }
        } else {
            detect(raw)?
        };
        observables.push(obs);
    }

    // --- Determine engines (use first observable's type for selection) ---
    let primary_type = &observables[0].obs_type;

    // Warn about unknown engine names
    let unknown = unknown_engines(&args.engines);
    if !unknown.is_empty() {
        eprintln!(
            "{} unknown engine(s): {}",
            "warning:".yellow().bold(),
            unknown.join(", ")
        );
    }

    // Warn if selected engines don't support the detected type
    if !args.engines.is_empty() {
        for name in &args.engines {
            if let Some(e) = find_engine(name) {
                if !e.supports(primary_type) && !args.quiet {
                    eprintln!(
                        "{} engine '{}' does not support type {}",
                        "warning:".yellow().bold(),
                        name,
                        primary_type
                    );
                }
            }
        }
    }

    let final_engines = resolve_engines(
        primary_type,
        &args.engines,
        &args.exclude,
        args.all_engines,
    );

    if final_engines.is_empty() {
        return Err(CyberbroError::ValidationError {
            input: String::new(),
            reason: format!(
                "no engines available for type {}. Use --engines to specify engines manually.",
                primary_type
            ),
        });
    }

    if !args.quiet {
        eprintln!(
            "Analyzing {} observable(s) as {} using {} engine(s): {}",
            observables.len(),
            primary_type.as_str().cyan(),
            final_engines.len(),
            final_engines.join(", ").dimmed()
        );
    }

    // --- Submit all observables as a single text block ---
    let text = observables
        .iter()
        .map(|o| o.value.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let http = client::CyberbroClient::new(&cfg.server, &cfg.api_prefix, cfg.verify_tls)?;

    // --- Spinner ---
    let spinner = if !args.quiet && fmt == OutputFormat::Table {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Waiting for analysis to complete…");
        Some(pb)
    } else {
        None
    };

    let spinner_ref = &spinner;
    let client::AnalysisOutcome { analysis_id, results_url, results: result_data } = http
        .analyze_and_wait(
            &text,
            &final_engines,
            args.ignore_cache,
            cfg.timeout_secs,
            cfg.poll_interval_secs,
            || {
                if let Some(pb) = spinner_ref {
                    pb.tick();
                }
            },
        )
        .await?;

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    if !args.quiet && fmt == OutputFormat::Table {
        eprintln!("Analysis complete (ID: {})", analysis_id.dimmed());
    }

    // --- Render results ---
    render(&result_data, &fmt, args.no_color, &results_url);

    Ok(())
}
