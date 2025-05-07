mod cli;
mod config;
mod runner;

use anyhow::Result;
use std::process;

fn main() -> Result<()> {
    let args = cli::parse_args()?;

    match &args.command {
        cli::Commands::Apply(opts) => {
            let profile = match config::load_profile(opts.file.as_path()) {
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
                println!("dry run enabled.");
            }
            match runner::run_mmdebstrap(&profile, opts.dry_run, opts.debug) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error running mmdebstrap: {}", e);
                    process::exit(1);
                }
            }
        }
        cli::Commands::Validate(opts) => {
            let profile = config::load_profile(opts.file.as_path())?;
            println!("validation successful:\n{:#?}", profile);
        }
    }

    Ok(())
}
