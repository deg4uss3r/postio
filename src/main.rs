use clap::{App, Arg};
use dirs::home_dir;

use std::io::{stdin, stdout, Write};
use std::process::exit;

mod postio;

use postio::Encryption;

fn main() {
    let app = App::new("Postio")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Ricky (Degausser) <Ricky@Hosfelt.io>")
        .about("Send and receive encrypted files")
        .arg(
            Arg::with_name("Config")
                .short("c")
                .long("config")
                .value_name("/path/to/config")
                .takes_value(true)
                .help("Sets a custom config file (defaults to $HOME/.postio/config)"),
        )
        .arg(
            Arg::with_name("Output")
                .short("o")
                .value_name("/path/to/output/directory")
                .help("Change output directory to something other than the current directory"),
        )
        .arg(
            Arg::with_name("User")
                .short("u")
                .takes_value(true)
                .value_name("User@email.com")
                .help("User to receive file"),
        )
        .arg(
            Arg::with_name("Encryption")
                .long("encrypt")
                .takes_value(true)
                .value_name("AES or ChaCha")
                .default_value("AES")
                .help("Set the encryption algorithm"),
        )
        .arg(
            Arg::with_name("All")
                .short("a")
                .long("all")
                .display_order(5)
                .help("Get all files at once"),
        )
        .arg(
            Arg::with_name("No_delete")
                .short("d")
                .long("no-delete")
                .display_order(4)
                .help("Do not delete files after getting them"),
        )
        .arg(
            Arg::with_name("Setup")
                .short("x")
                .long("setup")
                .display_order(1)
                .help("Create config file and populate settings"),
        )
        .arg(
            Arg::with_name("Send")
                .short("s")
                .takes_value(true)
                .display_order(6)
                .value_name("/file/to/send")
                .help("Send file to user")
                .requires("User"),
        )
        .arg(
            Arg::with_name("Get")
                .short("g")
                .value_name("number in queue")
                .takes_value(true)
                .display_order(3)
                .help("Gets file from queue"),
        )
        .arg(
            Arg::with_name("List")
                .short("l")
                .long("list")
                .value_name("List")
                .takes_value(false)
                .display_order(2)
                .help("List files in your queue"),
        )
        .arg(
            Arg::with_name("Clear")
                .short("Q")
                .long("clear")
                .conflicts_with_all(&[
                    "List",
                    "Get",
                    "Send",
                    "Setup",
                    "No_delete",
                    "All",
                    "Output",
                    "User",
                ])
                .help("Deletes all files in your queue")
                .takes_value(false),
        );

    let matches = app.clone().get_matches();

    if matches.is_present("Setup") {
        let user_defined_path = matches.value_of("Setup").unwrap_or("").to_string();

        let result: bool = postio::check_for_config(&user_defined_path); //check for config, not directory

        if result {
            println!(
                "Your config file exists at {} do you wish to continue setting a new one? [Y/N]: ",
                &user_defined_path
            );
            stdout().flush().expect("Unable to flush stdout");
            let mut config_continue = String::new();
            stdin()
                .read_line(&mut config_continue)
                .expect("Something went wrong capturing user input");
            config_continue.trim();
            config_continue.pop();

            if config_continue.to_lowercase() == "n" {
                exit(1);
            }
        }

        postio::create_config(user_defined_path);
    } else if matches.is_present("List")
        || matches.is_present("Send")
        || matches.is_present("Get")
        || matches.is_present("Clear")
    {
        let home_directory_path = home_dir().unwrap();
        let default_postio_path = home_directory_path.join(".postio/config");
        let config_file = matches
            .value_of("Config")
            .unwrap_or(default_postio_path.to_str().unwrap());

        let user_profile = postio::read_config(&config_file.to_string());

        if matches.is_present("List") {
            let file_list = postio::list_files_in_folder(
                &user_profile.email,
                &user_profile.file_store_region,
                &user_profile.file_store,
                true,
            );
            if file_list.len() == 0 {
                println!("No files in queue, send a file!");
            }
        } else if matches.is_present("Send") {
            let file_to_send = matches.value_of("Send").unwrap();
            let user_to_send_file = matches.value_of("User").unwrap();
            let enc: Encryption;

            if matches.value_of("Encryption").unwrap().to_lowercase() == "aes" {
                enc = Encryption::AES;
            } else if matches.value_of("Encryption").unwrap().to_lowercase() == "chacha" {
                enc = Encryption::Chacha;
            } else {
                println!("Error: unsupported encryption algorithm");
                exit(9);
            }

            postio::send_file(
                &file_to_send.to_string(),
                &user_to_send_file.to_string(),
                &user_profile,
                enc,
            );
        } else if matches.occurrences_of("Get") > 0 {
            let user_file = matches.value_of("Get");

            let mut file_to_get = None;

            if user_file != Some("") {
                file_to_get = Some(user_file.unwrap().to_string());
            }

            let output_directory = matches.value_of("Output").unwrap_or(".");
            let output_directory = shellexpand::full(output_directory).unwrap();
            let mut delete = true;
            let mut all_files = false;

            if matches.is_present("All") {
                all_files = true;
            }

            if matches.is_present("No_delete") {
                delete = false;
            }

            let enc;

            if matches.value_of("Encryption").unwrap().to_lowercase() == "aes" {
                enc = Encryption::AES;
            } else if matches.value_of("Encryption").unwrap().to_lowercase() == "chacha" {
                enc = Encryption::Chacha;
            } else {
                println!("Error: unsupported encryption algorithm");
                exit(9);
            }
            postio::get_file(
                file_to_get,
                &output_directory.to_string(),
                all_files,
                &user_profile,
                delete,
                enc,
            );
        } else if matches.is_present("Clear") {
            let file_list = postio::list_files_in_folder(
                &user_profile.email,
                &user_profile.file_store_region,
                &user_profile.file_store,
                false,
            );
            for file in file_list.iter() {
                postio::aws_file_deleter(
                    &user_profile.email,
                    &user_profile.file_store_region,
                    &user_profile.file_store,
                    file,
                );
            }
        }
    } else {
        let mut help = stdout();
        app.write_help(&mut help)
            .expect("Cannot Get help...I should see a doctor");
        print!("\n")
    }
}
