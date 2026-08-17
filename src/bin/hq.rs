fn main() {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.is_empty() {
        args.push("hq".into());
    }
    match hq::run(args) {
        Ok(out) => {
            println!("{out}");
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
