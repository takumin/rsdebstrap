//! Tests for shell completion functionality.
//!
//! This module tests the completions subcommand, ensuring that:
//! - Completions can be parsed for all supported shells
//! - Generation produces valid output without panicking
//! - The CLI correctly handles completion requests

use anyhow::Result;
use clap::{Parser, ValueEnum};
use clap_complete::Shell;
use rsdebstrap::cli::{Cli, Commands};

/// Test parsing the completions command for all supported shells.
#[test]
fn test_completions_command_parsing() -> Result<()> {
    let shells = [
        ("bash", Shell::Bash),
        ("zsh", Shell::Zsh),
        ("fish", Shell::Fish),
        ("powershell", Shell::PowerShell),
        ("elvish", Shell::Elvish),
    ];

    for (shell_str, expected_shell) in shells {
        let args = Cli::parse_from(["rsdebstrap", "completions", shell_str]);
        match args.command {
            Commands::Completions(opts) => {
                assert_eq!(opts.shell, expected_shell, "Mismatched shell for '{}'", shell_str);
            }
            _ => panic!("Expected Completions command for shell '{}'", shell_str),
        }
    }

    Ok(())
}

/// Test that completion generation doesn't panic for any supported shell.
#[test]
fn test_completions_generation() -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    let mut buffer = Vec::new();

    // Test that generation doesn't panic for each shell
    for shell in Shell::value_variants() {
        buffer.clear();
        generate(*shell, &mut cmd, "rsdebstrap", &mut buffer);
        assert!(!buffer.is_empty(), "Generated completion for {:?} was empty", shell);
    }

    Ok(())
}

/// Test that completions for various shells contain expected patterns.
#[test]
fn test_completion_contents() -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();

    let test_cases = [
        (Shell::Bash, &["rsdebstrap", "apply", "validate", "completions"] as &[_]),
        (Shell::Zsh, &["#compdef rsdebstrap", "apply", "validate"]),
        (Shell::Fish, &["rsdebstrap", "apply", "validate", "completions"]),
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

/// Integration test: Test actual CLI invocation for completions.
#[test]
fn test_cli_completions_output() -> Result<()> {
    let test_cases = [
        ("bash", &["rsdebstrap", "apply", "validate", "completions"] as &[_]),
        ("zsh", &["#compdef rsdebstrap", "apply", "validate"]),
    ];

    for (shell, patterns) in test_cases {
        let output = std::process::Command::new("cargo")
            .args(["run", "--quiet", "--", "completions", shell])
            .output()?;

        assert!(output.status.success(), "Command failed for shell '{}'", shell);

        let stdout = String::from_utf8(output.stdout)?;

        for pattern in patterns {
            assert!(
                stdout.contains(pattern),
                "Pattern '{}' not found in stdout for shell '{}'",
                pattern,
                shell
            );
        }
    }

    Ok(())
}

/// Integration test: Test completions help output.
#[test]
fn test_completions_help() -> Result<()> {
    let output = std::process::Command::new("cargo")
        .args(["run", "--quiet", "--", "completions", "--help"])
        .output()?;

    assert!(output.status.success(), "Command failed to execute");

    let stdout = String::from_utf8(output.stdout)?;

    // Verify help text contains shell options
    assert!(stdout.contains("shell"));
    assert!(stdout.contains("bash"));
    assert!(stdout.contains("zsh"));
    assert!(stdout.contains("fish"));

    Ok(())
}

/// Test that invalid shell names are rejected.
#[test]
fn test_invalid_shell_rejected() {
    let result = Cli::try_parse_from(["rsdebstrap", "completions", "invalid-shell"]);
    assert!(result.is_err(), "Expected parsing to fail for invalid shell");
}
