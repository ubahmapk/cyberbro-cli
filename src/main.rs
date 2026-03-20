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

use cli::{Cli, Command, EnginesCommand};
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
    let (analysis_id, result_data) = http
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
    render(&result_data, &fmt, args.no_color);

    Ok(())
}
