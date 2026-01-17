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

/// Test parsing the completions command with bash shell.
#[test]
fn test_completions_command_bash() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "bash"]);

    match args.command {
        Commands::Completions(opts) => {
            assert!(matches!(opts.shell, Shell::Bash));
        }
        _ => panic!("Expected Completions command"),
    }

    Ok(())
}

/// Test parsing the completions command with zsh shell.
#[test]
fn test_completions_command_zsh() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "zsh"]);

    match args.command {
        Commands::Completions(opts) => {
            assert!(matches!(opts.shell, Shell::Zsh));
        }
        _ => panic!("Expected Completions command"),
    }

    Ok(())
}

/// Test parsing the completions command with fish shell.
#[test]
fn test_completions_command_fish() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "fish"]);

    match args.command {
        Commands::Completions(opts) => {
            assert!(matches!(opts.shell, Shell::Fish));
        }
        _ => panic!("Expected Completions command"),
    }

    Ok(())
}

/// Test parsing the completions command with powershell shell.
#[test]
fn test_completions_command_powershell() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "powershell"]);

    match args.command {
        Commands::Completions(opts) => {
            assert!(matches!(opts.shell, Shell::PowerShell));
        }
        _ => panic!("Expected Completions command"),
    }

    Ok(())
}

/// Test parsing the completions command with elvish shell.
#[test]
fn test_completions_command_elvish() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "completions", "elvish"]);

    match args.command {
        Commands::Completions(opts) => {
            assert!(matches!(opts.shell, Shell::Elvish));
        }
        _ => panic!("Expected Completions command"),
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

/// Test that bash completions contain expected patterns.
#[test]
fn test_bash_completion_content() -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    let mut buffer = Vec::new();

    generate(Shell::Bash, &mut cmd, "rsdebstrap", &mut buffer);
    let output = String::from_utf8(buffer)?;

    // Verify the completion script contains key elements
    assert!(output.contains("rsdebstrap"));
    assert!(output.contains("apply"));
    assert!(output.contains("validate"));
    assert!(output.contains("completions"));

    Ok(())
}

/// Test that zsh completions contain expected patterns.
#[test]
fn test_zsh_completion_content() -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    let mut buffer = Vec::new();

    generate(Shell::Zsh, &mut cmd, "rsdebstrap", &mut buffer);
    let output = String::from_utf8(buffer)?;

    // Verify the completion script contains key elements
    assert!(output.contains("#compdef rsdebstrap"));
    assert!(output.contains("apply"));
    assert!(output.contains("validate"));

    Ok(())
}

/// Test that fish completions contain expected patterns.
#[test]
fn test_fish_completion_content() -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    let mut buffer = Vec::new();

    generate(Shell::Fish, &mut cmd, "rsdebstrap", &mut buffer);
    let output = String::from_utf8(buffer)?;

    // Verify the completion script contains key elements
    assert!(output.contains("rsdebstrap"));
    assert!(output.contains("apply"));
    assert!(output.contains("validate"));
    assert!(output.contains("completions"));

    Ok(())
}

/// Integration test: Test actual CLI invocation for bash completions.
#[test]
fn test_cli_completions_bash_output() -> Result<()> {
    let output = std::process::Command::new("cargo")
        .args(["run", "--quiet", "--", "completions", "bash"])
        .output()?;

    assert!(output.status.success(), "Command failed to execute");

    let stdout = String::from_utf8(output.stdout)?;

    // Verify bash completion script contains expected patterns
    assert!(stdout.contains("rsdebstrap"));
    assert!(stdout.contains("apply"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("completions"));

    Ok(())
}

/// Integration test: Test actual CLI invocation for zsh completions.
#[test]
fn test_cli_completions_zsh_output() -> Result<()> {
    let output = std::process::Command::new("cargo")
        .args(["run", "--quiet", "--", "completions", "zsh"])
        .output()?;

    assert!(output.status.success(), "Command failed to execute");

    let stdout = String::from_utf8(output.stdout)?;

    // Verify zsh completion script contains expected patterns
    assert!(stdout.contains("#compdef rsdebstrap"));
    assert!(stdout.contains("apply"));
    assert!(stdout.contains("validate"));

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
