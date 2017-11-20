extern crate clap;
extern crate openssl;
extern crate rand;
extern crate s3;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate toml;

use clap::{Arg, App, ArgGroup};
use std::env::home_dir;

mod postio;

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
            .takes_value(true)
            .help("User to receive file"))
        .arg(Arg::with_name("Input")
            .short("i")
            .takes_value(true)
            .help("Sets the input file to use"))
        .group(ArgGroup::with_name("Action")
            .required(true)
            .args(&["Send", "Get", "List", "Setup"]))
        .arg(Arg::with_name("Send")
            .short("s")
            .help("Send file to user")
            .requires("Input")
            .requires("User"))
        .arg(Arg::with_name("Get")
            .short("g")
            .help("Gets file from queue")
            .requires("Input"))
        .arg(Arg::with_name("All")
            .long("all")
            .help("Get all files at once"))
         .arg(Arg::with_name("No_delete")
            .long("no-delete")
            .help("Do not delete files after getting them"))       
        .arg(Arg::with_name("List")
            .short("l")
            .help("List files in your queue"))
        .arg(Arg::with_name("Setup")
            .long("setup")
            .help("Create config file and populate settings"))

        .get_matches();

if matches.is_present("Setup") {
    postio::create_config();
}
else {    
        let home_directory_path = home_dir().unwrap();
        let default_postio_path = home_directory_path.join(".postio/config");
        let config_file = matches.value_of("Config").unwrap_or(default_postio_path.to_str().unwrap());

        let user_profile = postio::read_config(&config_file.to_string());

        if matches.is_present("List") {
           postio::list_files_in_folder(&user_profile.email, &user_profile.file_store_region, &user_profile.file_store, true);
        }

        if matches.is_present("Send") {
            let file_to_send = matches.value_of("Input").unwrap();
            let user_to_send_file = matches.value_of("User").unwrap();
            postio::send_file(&file_to_send.to_string(), &user_to_send_file.to_string(), &user_profile);
        }

        if matches.is_present("Get") {
            let file_to_get = matches.value_of("Input").unwrap();
            let output_directory = matches.value_of("Output").unwrap_or(".");
            let mut delete = true;
            let mut all_files = false;

            if matches.is_present("All") {
                all_files = true;
            }

            if matches.is_present("No_delete") {
                delete = false;
            }

            postio::get_file(&file_to_get.to_string(), &output_directory.to_string(), all_files, &user_profile, delete);
        }
    }
}