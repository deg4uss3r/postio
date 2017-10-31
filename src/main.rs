extern crate clap;

use clap::{Arg, App, ArgGroup};

fn main() {
    let matches = App::new("Postio")
        .version("0.2.0")
        .author("Ricky (Degausser) <Ricky@Hosfelt.io>")
        .about("Send and receive encrypted files")
        .arg(Arg::with_name("Config")
            .short("c")
            .long("config")
            .value_name("config_file")
            .takes_value(true)
            .help("Sets a custom config file (defaults to ~/.postio/config)"))
        .arg(Arg::with_name("Output")
            .short("o")
            .value_name("output_directory")
            .help("Change output directory to something other than the current directory"))
        .arg(Arg::with_name("User")
            .short("u")
            .help("User to receive file"))
        .arg(Arg::with_name("Input")
            .short("i")
            .help("Sets the input file to use"))
        .group(ArgGroup::with_name("Action")
            .required(true)
            .args(&["Send", "Get", "List"]))
        .arg(Arg::with_name("Send")
            .short("s")
            .help("Send file to user")
            .requires("Input")
            .requires("User"))
        .arg(Arg::with_name("Get")
            .short("g")
            .help("Gets file from queue")
            .requires("Input"))
        .arg(Arg::with_name("List")
            .short("l")
            .help("List files in your queue"))

        .get_matches();
}