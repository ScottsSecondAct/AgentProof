fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = aegis_compiler::cli::cli_main(&args);
    std::process::exit(code);
}
