use clap::{Parser, error::ErrorKind};
use ewb_test_harness::cli::{Cli, dispatch};
use serde_json::json;
use std::io::Write;

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if json_requested {
                let payload = if informational {
                    json!({"ok": true, "command": "help", "data": {"text": error.to_string()}})
                } else {
                    json!({"ok": false, "error": {"code": "invalid_arguments", "message": error.to_string()}})
                };
                println!(
                    "{}",
                    serde_json::to_string(&payload).expect("JSON serialization")
                );
                std::process::exit(if informational { 0 } else { 2 });
            }
            error.exit();
        }
    };

    match dispatch(&cli) {
        Ok(outcome) => {
            let payload = json!({"ok": true, "command": outcome.command, "data": outcome.data});
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string(&payload).expect("JSON serialization")
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).expect("JSON serialization")
                );
            }
            std::process::exit(outcome.exit_code);
        }
        Err(error) => {
            if cli.json {
                let payload = json!({
                    "ok": false,
                    "error": {"code": "command_failed", "message": error.to_string()}
                });
                println!(
                    "{}",
                    serde_json::to_string(&payload).expect("JSON serialization")
                );
            } else {
                let _ = writeln!(std::io::stderr(), "ewb: {error:#}");
            }
            std::process::exit(2);
        }
    }
}
