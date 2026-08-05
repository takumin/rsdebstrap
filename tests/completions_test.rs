//! Tests for shell completion generation.
//!
//! Scope: the completions this crate emits for its own command tree. Parsing the
//! `completions <shell>` argument and rendering `--help` are clap's behavior, not
//! ours, so they are not retested here.

use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use rsdebstrap::cli::{Cli, Commands};

// The generated script must actually mention this crate's subcommands — an empty
// or truncated script would still "generate successfully".
#[test]
fn test_completion_contents() -> Result<()> {
    let mut cmd = Cli::command();

    let test_cases = [
        (Shell::Bash, &["rsdebstrap", "apply", "validate", "completions"] as &[_]),
        (Shell::Zsh, &["#compdef rsdebstrap", "apply", "validate"]),
        (Shell::Fish, &["rsdebstrap", "apply", "validate", "completions"]),
        (Shell::PowerShell, &["rsdebstrap", "apply", "validate", "completions"]),
        (Shell::Elvish, &["rsdebstrap", "apply", "validate", "completions"]),
    ];

    for (shell, patterns) in test_cases {
        let mut buffer = Vec::new();
        generate(shell, &mut cmd, "rsdebstrap", &mut buffer);
        let output = String::from_utf8(buffer)?;

        for pattern in patterns {
            assert!(
                output.contains(pattern),
                "Pattern '{}' not found in {:?} completions",
                pattern,
                shell
            );
        }
    }

    Ok(())
}

// The `shell` argument reaches the command handler intact.
#[test]
fn test_completions_command_carries_shell() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "bash"]);
    match args.command {
        Commands::Completions(opts) => assert_eq!(opts.shell, Shell::Bash),
        other => panic!("Expected Completions command, got: {:?}", other),
    }

    Ok(())
}
