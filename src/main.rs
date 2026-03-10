use wsh::app;
use wsh::cli::Cli;

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

    let cli = <Cli as clap::Parser>::parse();
    let code = match app::run(cli) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(code);
}
