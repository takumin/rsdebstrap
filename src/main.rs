mod cli;
mod config;
mod runner;

use anyhow::Result;
use std::process;

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    match &args.command {
        cli::Commands::Apply(opts) => {
            let file_path = opts.file.as_deref().unwrap_or("config.yaml");
            let profile = match config::load_profile(file_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            };
            if opts.debug {
                println!("loaded profile: {:#?}", profile);
            }
            if opts.dry_run {
                println!("dry run enabled. Command will not be executed.");
                return Ok(());
            }
            let _ = runner::run_mmdebstrap(&profile, opts);
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(&opts.file)?;
            println!("validation successful:\n{:#?}", profile);
        }
    }

    Ok(())
}
