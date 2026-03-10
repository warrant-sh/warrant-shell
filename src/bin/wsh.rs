use wsh::app;
use wsh::cli::Cli;

use clap::Parser;

fn main() {
    wsh::scrub_wsh_env_vars();

    let args = std::env::args().collect::<Vec<_>>();
    match app::run_startup_mode(&args) {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }

    let cli = Cli::parse();
    if let Err(err) = app::run(cli) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
