mod cli;
mod config;
mod runner;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    match &args.command {
        cli::Commands::Apply(opts) => {
            let file_path = opts.file.as_deref().unwrap_or("config.yaml");
            let profile = config::load_profile(file_path)
                .with_context(|| format!("failed to load profile from {}", file_path))?;

            if opts.debug {
                println!("loaded profile: {:#?}", profile);
            }
            if opts.dry_run {
                println!("dry run enabled. Command will not be executed.");
                return Ok(());
            }
            runner::run_mmdebstrap(&profile, opts).with_context(|| "failed to run mmdebstrap")?;
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(&opts.file)
                .with_context(|| format!("failed to validate profile from {}", &opts.file))?;
            println!("validation successful:\n{:#?}", profile);
        }
    }

    Ok(())
}
