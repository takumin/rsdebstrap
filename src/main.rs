use anyhow::Result;
use clap::CommandFactory;
use clap_complete::generate;
use std::io;

use rsdebstrap::{cli, executor, init_logging, run_apply, run_validate};

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    // Handle completions subcommand before setting up logging
    // (completion output should be clean without any logging)
    if let cli::Commands::Completions(opts) = &args.command {
        let mut cmd = cli::Cli::command();
        generate(opts.shell, &mut cmd, "rsdebstrap", &mut io::stdout());
        return Ok(());
    }

    let log_level = match &args.command {
        cli::Commands::Apply(opts) => opts.log_level,
        cli::Commands::Validate(opts) => opts.log_level,
        cli::Commands::Completions(_) => unreachable!("completions handled above"),
    };

    init_logging(log_level)?;

    match &args.command {
        cli::Commands::Apply(opts) => {
            let executor = executor::RealCommandExecutor {
                dry_run: opts.dry_run,
            };

            run_apply(opts, &executor)?;
        }
        cli::Commands::Validate(opts) => run_validate(opts)?,
        cli::Commands::Completions(_) => {
            unreachable!("completions handled earlier");
        }
    }

    Ok(())
}
