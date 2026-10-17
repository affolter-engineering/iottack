use clap::{Arg, ArgAction, ArgMatches, Command};
use iottack::{CliArg, PluginConfig, PluginRegistry, PluginResult, PluginStatus};
use std::fs;

/// Dynamic CLI builder
fn clap_arg(a: &CliArg) -> Arg {
    let flag: &'static str = Box::leak(a.name.replace('_', "-").into_boxed_str());
    let mut arg = Arg::new(a.name).long(flag).help(a.help);
    if let Some(s) = a.short {
        arg = arg.short(s);
    }
    if a.is_flag {
        arg = arg.action(ArgAction::SetTrue);
    } else {
        arg = arg.value_name(a.value_name);
        match a.default {
            Some(d) => arg = arg.default_value(d),
            None => arg = arg.required(false),
        }
    }
    arg
}

/// Builds the CLI application dynamically based on the registered plugins.
fn build_cli(registry: &PluginRegistry) -> Command {
    // Group plugin names by their first path segment (e.g. "serial", "network").
    let mut groups: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for name in registry.list() {
        if let Some(group) = name.split('/').next() {
            groups
                .entry(group.to_string())
                .or_default()
                .push(name.to_string());
        }
    }

    let mut app = Command::new("iottack")
        .version(env!("CARGO_PKG_VERSION"))
        .about("IoT protocol pentesting framework")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .global(true)
                .help("Increase log verbosity (-v, -vv, -vvv)"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .global(true)
                .value_name("FILE")
                .help("Save plugin output to a file"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .global(true)
                .value_name("FORMAT")
                .default_value("text")
                .value_parser(["text", "json"])
                .help("Output format for --output [text, json]"),
        )
        .subcommand(Command::new("list").about("List all registered plugins"))
        .subcommand(
            Command::new("run")
                .about("Run a plugin by name with key=value arguments")
                .arg(
                    Arg::new("name")
                        .required(true)
                        .help("Plugin name (e.g. serial/baud-scan)"),
                )
                .arg(
                    Arg::new("args")
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .num_args(0..)
                        .help("Config arguments as key=value pairs"),
                ),
        );

    for (group, plugin_names) in &groups {
        let about = match group.as_str() {
            "serial" => "Serial/UART sub-commands",
            "network" => "Network protocol sub-commands",
            "host" => "Host enumeration sub-commands",
            _ => "Sub-commands",
        };
        let group_s: &'static str = Box::leak(group.clone().into_boxed_str());
        let mut group_cmd = Command::new(group_s).about(about);
        for plugin_name in plugin_names {
            let plugin = registry.get(plugin_name).unwrap();
            let meta = plugin.meta();
            let subname = plugin_name.splitn(2, '/').nth(1).unwrap();
            if subname == group.as_str() {
                // Plugin name matches group. Expose args directly on the group command
                // so the user types `iottack <group>` instead of `iottack <group> <group>`.
                for a in meta.cli_args {
                    group_cmd = group_cmd.arg(clap_arg(a));
                }
            } else {
                let subname_s: &'static str = Box::leak(subname.to_string().into_boxed_str());
                let mut sub = Command::new(subname_s).about(meta.summary);
                for a in meta.cli_args {
                    sub = sub.arg(clap_arg(a));
                }
                group_cmd = group_cmd.subcommand(sub);
            }
        }
        app = app.subcommand(group_cmd);
    }

    app
}

/// Parses the command-line arguments and constructs a PluginConfig from them.
fn config_from_matches(cli_args: &[CliArg], m: &ArgMatches) -> PluginConfig {
    let mut cfg = PluginConfig::new();
    for a in cli_args {
        if a.is_flag {
            cfg.set(a.name, if m.get_flag(a.name) { "true" } else { "false" });
        } else if let Some(v) = m.get_one::<String>(a.name) {
            cfg.set(a.name, v.as_str());
        }
    }
    cfg
}

/// Routes the command-line arguments to the appropriate plugin and returns its name and configuration if found.
fn route(matches: &ArgMatches, registry: &PluginRegistry) -> Option<(String, PluginConfig)> {
    for name in registry.list() {
        let mut parts = name.splitn(2, '/');
        let (Some(group), Some(subname)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let Some(gm) = matches.subcommand_matches(group) {
            if subname == group {
                // Direct group command (no nested subcommand); only match when the user
                // didn't pick a subcommand of this group.
                if gm.subcommand_name().is_none() {
                    let plugin = registry.get(name).unwrap();
                    let cfg = config_from_matches(plugin.meta().cli_args, gm);
                    return Some((name.to_string(), cfg));
                }
            } else if let Some(sm) = gm.subcommand_matches(subname) {
                let plugin = registry.get(name).unwrap();
                let cfg = config_from_matches(plugin.meta().cli_args, sm);
                return Some((name.to_string(), cfg));
            }
        }
    }
    None
}

/// Formats the result of a plugin execution as a human-readable string.
fn format_text(result: &PluginResult) -> String {
    let elapsed = result
        .finished_at
        .signed_duration_since(result.started_at)
        .num_milliseconds();
    let elapsed_str = if elapsed >= 1_000 {
        format!("{:.2} s", elapsed as f64 / 1_000.0)
    } else {
        format!("{elapsed} ms")
    };
    let status_str = match &result.status {
        PluginStatus::Pass => "pass",
        PluginStatus::Fail => "fail",
        PluginStatus::Error(_) => "error",
        PluginStatus::Skipped => "skipped",
    };

    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("Plugin name:    {}\n", result.plugin));
    out.push_str(&format!(
        "Date:           {}\n",
        result.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!("Execution time: {elapsed_str}\n"));
    out.push_str(&format!("Status:         {status_str}\n"));
    out.push('\n');
    if result.findings.is_empty() {
        out.push_str("  No findings.\n");
    } else {
        for f in &result.findings {
            out.push_str(&format!("{}\n", f.title));
            out.push_str(&format!("  {}\n", f.description));
            if let Some(ev) = &f.evidence {
                out.push_str(&format!("  Evidence: {ev:?}\n"));
            }
            out.push('\n');
        }
    }
    out
}

/// Prints the result of a plugin execution to the console.
fn print_result(result: &PluginResult) {
    let elapsed = result
        .finished_at
        .signed_duration_since(result.started_at)
        .num_milliseconds();
    let elapsed_str = if elapsed >= 1_000 {
        format!("{:.2} s", elapsed as f64 / 1_000.0)
    } else {
        format!("{elapsed} ms")
    };
    let status_str = match &result.status {
        PluginStatus::Pass => "\x1b[32mpass\x1b[0m",
        PluginStatus::Fail => "\x1b[31mfail\x1b[0m",
        PluginStatus::Error(_) => "\x1b[35merror\x1b[0m",
        PluginStatus::Skipped => "\x1b[33mskipped\x1b[0m",
    };
    println!();
    println!("Plugin name:    {}", result.plugin);
    println!("Execution time: {elapsed_str}");
    println!("Status:         {status_str}");
    println!(
        "Date:           {}",
        result.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();
    if result.findings.is_empty() {
        println!("  No findings.");
    } else {
        for f in &result.findings {
            println!("{}", f.title);
            println!("  {}", f.description);
            if let Some(ev) = &f.evidence {
                println!("  Evidence: {ev:?}");
            }
            println!();
        }
    }
}

/// Saves the result of a plugin execution to a file in the specified format.
fn save_result(result: &PluginResult, path: &str, format: &str) -> anyhow::Result<()> {
    let content = match format {
        "json" => serde_json::to_string_pretty(result)?,
        _ => format_text(result),
    };
    fs::write(path, content)?;
    println!("Output saved to {path}");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let registry = PluginRegistry::new();
    let matches = build_cli(&registry).get_matches();

    let level = match matches.get_count("verbose") {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    let output: Option<&String> = matches.get_one("output");
    let format: &str = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("text");

    let emit = |result: PluginResult| -> anyhow::Result<()> {
        print_result(&result);
        if let Some(path) = output {
            save_result(&result, path, format)?;
        }
        Ok(())
    };

    match matches.subcommand() {
        Some(("list", _)) => {
            println!("Registered plugins:");
            for name in registry.list() {
                let plugin = registry.get(name).unwrap();
                println!("  {:<30}  {}", name, plugin.meta().summary);
            }
        }
        Some(("run", m)) => {
            let name = m.get_one::<String>("name").unwrap();
            let raw: Vec<&String> = m.get_many("args").unwrap_or_default().collect();
            let mut cfg = PluginConfig::new();
            for kv in raw {
                if let Some((k, v)) = kv.split_once('=') {
                    cfg.set(k.trim(), v.trim());
                }
            }
            emit(registry.run(name, &cfg)?)?;
        }
        _ => {
            if let Some((plugin_name, cfg)) = route(&matches, &registry) {
                emit(registry.run(&plugin_name, &cfg)?)?;
            }
        }
    }

    Ok(())
}
