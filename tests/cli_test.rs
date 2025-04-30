use anyhow::Result;
use clap::Parser;
use rsdebstrap::cli::{Cli, Commands};

#[test]
fn test_parse_apply_command() -> Result<()> {
    let args = Cli::parse_from(["rsdebstrap", "apply", "--file", "test.yml"]);

    match args.command {
        Commands::Apply(opts) => {
            assert_eq!(opts.file, Some("test.yml".to_string()));
            assert!(!opts.dry_run);
            assert!(!opts.debug);
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
        "--debug",
    ]);

    match args.command {
        Commands::Apply(opts) => {
            assert_eq!(opts.file, Some("test.yml".to_string()));
            assert!(opts.dry_run);
            assert!(opts.debug);
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
            assert_eq!(opts.file, "test.yml");
        }
        _ => panic!("Expected Validate command"),
    }

    Ok(())
}
