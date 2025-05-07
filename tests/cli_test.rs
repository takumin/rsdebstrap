use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use rsdebstrap::cli::{Cli, Commands, LogLevel};

#[test]
fn test_parse_apply_command() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "apply", "--file", "test.yml"]);

    match args.command {
        Commands::Apply(opts) => {
            assert_eq!(opts.file, Utf8PathBuf::from("test.yml"));
            assert_eq!(opts.log_level, LogLevel::Info);
            assert!(!opts.dry_run);
        }
        _ => panic!("Expected Apply command"),
    }

    Ok(())
}

#[test]
fn test_parse_apply_command_with_flags() -> Result<()> {
    let args = Cli::parse_from([
        "rsdebstrap",
        "apply",
        "--file",
        "test.yml",
        "--dry-run",
        "--log-level",
        "error",
    ]);

    match args.command {
        Commands::Apply(opts) => {
            assert_eq!(opts.file, Utf8PathBuf::from("test.yml"));
            assert_eq!(opts.log_level, LogLevel::Error);
            assert!(opts.dry_run);
        }
        _ => panic!("Expected Apply command"),
    }

    Ok(())
}

#[test]
fn test_parse_validate_command() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "validate", "--file", "test.yml"]);

    match args.command {
        Commands::Validate(opts) => {
            assert_eq!(opts.file, Utf8PathBuf::from("test.yml"));
        }
        _ => panic!("Expected Validate command"),
    }

    Ok(())
}
