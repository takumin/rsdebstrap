use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;
use std::io;
use std::sync::Arc;

#[cfg(feature = "schema")]
use rsdebstrap::run_schema;
use rsdebstrap::{cli, executor, init_logging, run_apply, run_validate};

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    // Handle stdout-only subcommands before setting up logging
    // (their output should be clean without any logging noise).
    match &args.command {
        cli::Commands::Completions(opts) => {
            let mut cmd = cli::Cli::command();
            generate(opts.shell, &mut cmd, "rsdebstrap", &mut io::stdout());
            return Ok(());
        }
        #[cfg(feature = "schema")]
        cli::Commands::Schema => return run_schema(),
        _ => {}
    }

    let log_level = match &args.command {
        cli::Commands::Apply(opts) => opts.common.log_level,
        cli::Commands::Validate(opts) => opts.common.log_level,
        cli::Commands::Completions(_) => unreachable!("stdout-only subcommands handled above"),
        #[cfg(feature = "schema")]
        cli::Commands::Schema => unreachable!("stdout-only subcommands handled above"),
    };

    init_logging(log_level)?;

    match &args.command {
        cli::Commands::Apply(opts) => {
            let executor = Arc::new(executor::RealCommandExecutor {
                dry_run: opts.dry_run,
            });

            run_apply(opts, executor)?;
        }
        cli::Commands::Validate(opts) => run_validate(opts)?,
        cli::Commands::Completions(_) => unreachable!("stdout-only subcommands handled earlier"),
        #[cfg(feature = "schema")]
        cli::Commands::Schema => unreachable!("stdout-only subcommands handled earlier"),
    }

    Ok(())
}
