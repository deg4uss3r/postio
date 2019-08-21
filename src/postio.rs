use dirs::home_dir;
use openssl::sha;
use openssl::symm::Cipher;
use openssl::symm::encrypt;
use openssl::symm::decrypt;

use rand::prelude::*;
use rand_os::OsRng;

use s3::bucket::Bucket;
use s3::credentials::Credentials;
use s3::error::{ErrorKind as EK, S3Error};
use serde::{Deserialize, Serialize};
use shellexpand;
use toml::{from_str, to_string};

use x25519_dalek::StaticSecret;
use x25519_dalek::PublicKey;
use x25519_dalek::SharedSecret;

use std::env::var;
use std::fs::{create_dir_all, remove_file, File, OpenOptions};
use std::io::prelude::*;
use std::io::{stdin, stdout, Error, ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::exit;
use std::str;

//Struct to deserialze the config file into
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub email: String,
    pub private_key: String,
    pub public_key: String,
    pub file_store: String,
    pub file_store_region: String,
    pub public_key_store: String,
    pub public_key_store_region: String,
}

//struct that is stored on the AWS instance
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileBlob {
    pub file: Vec<u8>,
    pub iv: Vec<u8>,
    pub from: String,
}

pub enum Encryption {
    AES,
    Chacha,
}

//checks path for existence of config file
pub fn check_for_config(user_defined_path: &String) -> bool {
    let user_path = Path::new(&user_defined_path);

    if user_path.is_dir() {
        return false;
    } else {
        if user_path.exists() {
            let mut config_file_holder = match File::open(&user_path) {
                Ok(x) => x,
                Err(_) => {
                    return false;
                }
            };

            let mut config_file = String::new();
            config_file_holder.read_to_string(&mut config_file).unwrap();

            let postio_config: Result<Config, _> = from_str(&config_file);
            match postio_config {
                Ok(_) => {
                    return true;
                }
                Err(_) => {
                    return false;
                }
            };
        } else {
            return false;
        }
    }
}

pub fn check_config_files_config(postio_config: &Config) -> Result<(), Error> {
    if !Path::new(&postio_config.private_key).is_file() {
        let custom_error = Error::new(
            ErrorKind::NotFound,
            format!(
                "Private key not found at path {} (in config file)",
                &postio_config.private_key
            ),
        );
        return Err(custom_error);
    }
    if !Path::new(&postio_config.public_key).is_file() {
        let custom_error = Error::new(
            ErrorKind::NotFound,
            format!(
                "Public key not found at path {} (in config file)",
                &postio_config.public_key
            ),
        );
        return Err(custom_error);
    }

    Ok(())
}

//function creates a config file for the user via stdin
pub fn create_config(user_defined_path: String) {
    //TODO update logic, propogate postio_dir and so through function

    //safely getting default location for the config
    let home_dir = home_dir().unwrap();
    let mut postio_dir = home_dir.join(".postio");

    if !postio_dir.is_dir() {
        create_dir_all(&postio_dir).expect(&format!("Error creating directory: {:?}", &postio_dir));
    }

    let postio_config_file_path;

    if user_defined_path == "" {
        postio_dir = home_dir.join(".postio");
        postio_config_file_path = postio_dir.join("config");
    } else {
        let mut user_path =
            Path::new(&(shellexpand::full(&user_defined_path).unwrap()).into_owned()).to_path_buf();

        if user_path.is_dir() {
            postio_dir = user_path.to_path_buf();
            user_path = user_path.join("postio_config");
        } else {
            user_path = user_path.to_path_buf();
        }

        postio_config_file_path = user_path;
    }

    let mut private_key_path = String::new();
    let mut public_key_path = String::new();

    //get EC keys or create them
    print!("Do you have x25519 pub/private keys? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    let mut key_maybe = String::new();
    stdin()
        .read_line(&mut key_maybe)
        .expect("Something went wrong capturing user input");
    key_maybe.trim().to_uppercase();
    key_maybe.pop();

    if key_maybe == "Y" {
        print!("Full path to your public key: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut public_key_path)
            .expect("Something went wrong capturing user input");
        public_key_path = public_key_path.trim().to_string();
        public_key_path.pop();
        public_key_path = (shellexpand::full(&public_key_path).unwrap()).to_string();

        print!("Full path to your private key: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut private_key_path)
            .expect("Something went wrong capturing user input");
        private_key_path = private_key_path.trim().to_string();
        private_key_path.pop();
        private_key_path = (shellexpand::full(&private_key_path).unwrap()).to_string();
    } else if key_maybe == "N" {
        //generate keys for them if they say no

        let mut keys_rand = OsRng::new().unwrap();
        let private_key = StaticSecret::new(&mut keys_rand);
        let public_key = PublicKey::from(&private_key);

        let private_key_dir = postio_dir.to_owned().join("private_key.secret");
        let mut sender_priv = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(private_key_dir)
            .expect("Unable to write file to disk");
        sender_priv
            .write_all(&private_key.to_bytes())
            .expect("Unable to write private key");


        let mut sender_pub =
            File::create(postio_dir.to_owned().join("public_key").as_path()).unwrap();
        sender_pub
            .write_all(public_key.as_bytes())
            .expect("Unable to create public key");

        private_key_path = home_dir
            .to_owned()
            .join(".postio/private_key.secret")
            .as_path()
            .to_str()
            .unwrap()
            .to_owned();
        public_key_path = home_dir
            .to_owned()
            .join(".postio/public_key")
            .as_path()
            .to_str()
            .unwrap()
            .to_owned();
    } else {
        println!("Yeah it was a yes or no question... [Y/N]");
        exit(1);
    }

    let mut user_email = String::new();
    print!("Please enter the email address you wish to use: ");
    stdout().flush().expect("Unable to flush stdout");
    stdin()
        .read_line(&mut user_email)
        .expect("Something went wrong capturing user input");
    user_email = user_email.trim().to_string();
    user_email.pop();

    //getting S3 file store information
    let mut postio_file_store_answer = String::new();
    let mut postio_file_store = String::new();
    let mut postio_file_store_region = String::new();

    print!("Do you have an AWS S3 store setup for files? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    stdin()
        .read_line(&mut postio_file_store_answer)
        .expect("Something went wrong capturing user input");
    postio_file_store_answer = postio_file_store_answer.trim().to_string();
    postio_file_store_answer.pop();

    if postio_file_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 store name: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut postio_file_store)
            .expect("Something went wrong capturing user input");
        postio_file_store = postio_file_store.trim().to_string();
        postio_file_store.pop();

        print!("S3 store region: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut postio_file_store_region)
            .expect("Something went wrong capturing user input");
        postio_file_store_region = postio_file_store_region.trim().to_string();
        postio_file_store_region.pop();
    } else if postio_file_store_answer.to_uppercase() == "N".to_string() {
        postio_file_store = "postio".to_string();
        postio_file_store_region = "eu-west-2".to_string();
    } else {
        println!("Expecting Y or N...");
        exit(1);
    }

    //getting S3 key storage information
    let mut postio_key_store_answer = String::new();
    let mut postio_key_store = String::new();
    let mut postio_key_store_region = String::new();

    print!("Do you have an AWS S3 store setup for public keys? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    stdin()
        .read_line(&mut postio_key_store_answer)
        .expect("Failed reading user input");
    postio_key_store_answer = postio_key_store_answer.trim().to_string();
    postio_key_store_answer.pop();

    if postio_key_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 public key store name: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut postio_key_store)
            .expect("Failed reading user input");
        postio_key_store = postio_key_store.trim().to_string();
        postio_key_store.pop();

        print!("S3 store region: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin()
            .read_line(&mut postio_key_store_region)
            .expect("Failed reading user input");
        postio_key_store_region = postio_key_store_region.trim().to_string();
        postio_key_store_region.pop();
    } else if postio_key_store_answer.to_uppercase() == "N".to_string() {
        postio_key_store = "postio-keys".to_string();
        postio_key_store_region = "eu-central-1".to_string();
    } else {
        println!("Expecting Y or N...");
        exit(1);
    }

    //Using gathered information from the user to crate the struct
    let postio_config_content: Config = Config {
        email: user_email,
        private_key: private_key_path,
        public_key: public_key_path,
        file_store: postio_file_store,
        file_store_region: postio_file_store_region,
        public_key_store: postio_key_store,
        public_key_store_region: postio_key_store_region,
    };

    //using new config to send public key to keystore for future use
    let user_name = &postio_config_content.email;
    let pub_key_reg = &postio_config_content.public_key_store_region;
    let pub_key_bucket = &postio_config_content.public_key_store;
    let file_store_reg = &postio_config_content.file_store_region;
    let file_store = &postio_config_content.file_store;

    //adding user to database
    println!(
        "Adding public keys for {} to {}:{}",
        user_name, pub_key_reg, pub_key_bucket
    );
    add_users_folder(user_name, pub_key_reg, pub_key_bucket).unwrap();
    println!(
        "Adding file queue for {} to {}:{}",
        user_name, file_store_reg, file_store
    );
    add_users_folder(user_name, file_store_reg, file_store).unwrap();

    //opening public key
    let mut pub_key = Vec::new();
    let mut pub_key_file = File::open(postio_config_content.public_key.to_owned()).unwrap();
    pub_key_file
        .read_to_end(&mut pub_key)
        .expect("Unable to read public key");

    //sending public key
    create_file_on_aws(
        &user_name,
        &"public_key".to_string(),
        pub_key,
        &pub_key_reg,
        &pub_key_bucket,
    ).unwrap();

    //serializing config file
    let postio = to_string(&postio_config_content).unwrap();

    //writing config file to ~/.postio or user defined directory (create all directories if they do not exist)
    let postio_config_file = File::create(&postio_config_file_path);

    match postio_config_file {
        Ok(mut postio_config_file) => postio_config_file
            .write_all(&postio.as_bytes())
            .expect("Cannot write postio config file"),
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                create_dir_all(postio_dir)
                    .expect("Error could not create the config file directory");
                let mut postio_config_file = File::create(&postio_config_file_path)
                    .expect("Error couldn't create file/directory path!");
                postio_config_file
                    .write_all(&postio.as_bytes())
                    .expect("Cannot write postio config file");
            } else {
                println!("Error : {} ", e);
                exit(1);
            }
        }
    }
}

//Reads and returns the config from file to struct
pub fn read_config(config_file_path: &String) -> Config {
    //opening and deserializing config
    let mut config_file_holder = match File::open(&config_file_path) {
        Ok(x) => x,
        Err(e) => {
            println!("Error! Couldn't open file: {}", e);
            exit(1);
        }
    };
    let mut config_file = String::new();
    config_file_holder.read_to_string(&mut config_file).unwrap();

    let postio_config = from_str(&config_file);

    //getting config file
    match postio_config {
        Err(e) => {
            let mut delete_answer = String::new();
            print!(
                "Error in your config file, please check your settings!\n\tWould you like to delete the config file? [Y/N]: "
            );
            stdout()
                .flush()
                .expect("Unable to flush output, that's bad");
            stdin()
                .read_line(&mut delete_answer)
                .expect("User input failed..Sorry");
            delete_answer = delete_answer.trim().to_string();
            delete_answer.pop();

            if delete_answer.to_uppercase() == "Y".to_string() {
                remove_file(&config_file_path).unwrap();
                println!("Config file deleted, run the program again to set it up!");
                exit(99);
            } else {
                println!("File not deleted please check your configurations: {}", e);
                exit(1);
            }
        }

        Ok(config) => {
            return config;
        }
    }
}

fn open_private_key(pconfig: &Config) -> Result<[u8; 32], Error>{
    let file_path = &pconfig.private_key;
    let mut file = File::open(file_path)?;
    
    let mut key = [0u8; 32];
    file.read_exact(&mut key)?;

    Ok(key)
}

fn open_receiver_public_key(to_user: &String, pconfig: &Config) -> Result<[u8; 32], Error> {
    let public_key_string = aws_file_getter(
        &"public_key".to_string(),
        &to_user,
        &pconfig.public_key_store_region,
        &pconfig.public_key_store,
    ).unwrap();

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(public_key_string.as_slice());

    Ok(public_key)
}

fn create_shared_secret(private_key: [u8; 32], public_key: [u8; 32]) -> Result<SharedSecret, Error> {
    let k_secret = StaticSecret::from(private_key);
    let k_public = PublicKey::from(public_key);
    let shared = k_secret.diffie_hellman(&k_public);

    Ok(shared)
}

fn open_sender_public_key(to_user: &String, pconfig: &Config) -> Result<[u8; 32], Error> {
    let public_key_string = aws_file_getter_withoutsha(
        &"public_key".to_string(),
        &to_user,
        &pconfig.public_key_store_region,
        &pconfig.public_key_store,
    ).unwrap();

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(public_key_string.as_slice());

    Ok(public_key)
}

//AES Encryption (for the file)
pub fn aes_encrypter(file_path: String, pconfig: Config, to_user: String) -> FileBlob {
    let mut iv = Vec::new();
    let mut rng = rand::thread_rng();

    //checking keys in postio config
    check_config_files_config(&pconfig).expect("Error, something is wrong with your config file");

    //randomizing IV (16 bytes)
    for _ in 0..16 {
        iv.push(rng.gen::<u8>());
    }

    //loading private key
    let key = open_private_key(&pconfig).unwrap();

    //Getting public key of sending user
    let user_public_key = open_receiver_public_key(&to_user, &pconfig).unwrap();

    //Generating the shared secret
    let s_key = create_shared_secret(key, user_public_key).unwrap();

    //opening file to encrypt
    let path_expansion = shellexpand::full(&file_path)
        .expect("Cannot expand file path")
        .to_string();
    let full_file_path = Path::new(&path_expansion);
    let mut unencrypted_file = File::open(full_file_path).unwrap();
    let mut file_buffer = Vec::new();
    unencrypted_file
        .read_to_end(&mut file_buffer)
        .expect("Unable to read file");

    let encrypted_file = encrypt(
        Cipher::aes_256_cbc(),
        s_key.as_bytes(),
        Some(&iv),
        &file_buffer,
    );

    //Preparing to put the user hash into the file blob 
    let user_sha = sha::sha512(pconfig.email.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let user_sha_string = vec_to_hex_string(user_sha_vec);

    //putting file, IV, together into a blob and sending to AWS S3
    let file_blob_for_aws: FileBlob = FileBlob {
        file: encrypted_file.unwrap(),
        iv: iv,
        from: user_sha_string,
    };

    //return blob
    file_blob_for_aws
}

//ChaCha20 Encryptor
pub fn chacha_encrypter(file_path: String, pconfig: Config, to_user: String) -> FileBlob {
    let mut iv = Vec::new();
    let mut rng = rand::thread_rng();

    //checking keys in postio config
    check_config_files_config(&pconfig).expect("Error, something is wrong with your config file");

    //randomizing IV (16 bytes)
    for _ in 0..16 {
        iv.push(rng.gen::<u8>());
    }

    let key = open_private_key(&pconfig).unwrap();

    //Getting receiver Public Key
    let user_public_key = open_receiver_public_key(&to_user, &pconfig).unwrap();

    //Generating the shared secret
    let s_key = create_shared_secret(key, user_public_key).unwrap();

    //opening file to encrypt
    let path_expansion = shellexpand::full(&file_path)
        .expect("Cannot expand file path")
        .to_string();
    let full_file_path = Path::new(&path_expansion);
    let mut unencrypted_file = File::open(full_file_path).unwrap();
    let mut file_buffer = Vec::new();
    unencrypted_file
        .read_to_end(&mut file_buffer)
        .expect("Unable to read file");

    let encrypted_file = encrypt(Cipher::chacha20(), s_key.as_bytes(), Some(&iv), &file_buffer);

    //Preparing to put the user hash into the file blob 
    let user_sha = sha::sha512(pconfig.email.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let user_sha_string = vec_to_hex_string(user_sha_vec);

    //putting file, IV, together into a blob and sending to AWS S3
    let file_blob_for_aws: FileBlob = FileBlob {
        file: encrypted_file.unwrap(),
        iv: iv,
        from: user_sha_string,
    };

    //return blob
    file_blob_for_aws
}

//AES Decryption
pub fn aes_decrypter(out_file_path: String, file_from_aws: FileBlob, postio_config: Config) {
    //disecting fileblob from AWS
    let encrypted = file_from_aws.file;
    let key = open_private_key(&postio_config).unwrap();
    let iv = file_from_aws.iv;
    let from_user = file_from_aws.from;

    let out_file_holder = shellexpand::full(&out_file_path)
        .expect("Cannot convert output directory to path!")
        .to_string();

    check_config_files_config(&postio_config)
        .expect("Error, something is wrong with your config file");

    //Getting sender public key
    let user_public_key = open_sender_public_key(&from_user, &postio_config).unwrap();

    //Generating the shared secret
    let s_key = create_shared_secret(key, user_public_key).unwrap();

    //decrypting file with iv,key
    let unencrypted = decrypt(
        Cipher::aes_256_cbc(),
        s_key.as_bytes(),
        Some(&iv),
        &encrypted,
    );

    //writing file out
    let fileout = Path::new(&out_file_holder);
    let mut decrypted_file_path = File::create(fileout).expect("Unable to write file to disk");
    decrypted_file_path
        .write_all(&unencrypted.unwrap())
        .expect("unable to write encrypted file");
}

//ChaCha20 Decryption
pub fn chacha_decrypter(out_file_path: String, file_from_aws: FileBlob, postio_config: Config) {
    //disecting fileblob from AWS
    let encrypted = file_from_aws.file;
    let key = open_private_key(&postio_config).unwrap();
    let iv = file_from_aws.iv;
    let from_user = file_from_aws.from;

    let out_file_holder = shellexpand::full(&out_file_path)
        .expect("Cannot convert output directory to path!")
        .to_string();

    check_config_files_config(&postio_config)
        .expect("Error, something is wrong with your config file");

    //Getting sender public key
    let user_public_key = open_sender_public_key(&from_user, &postio_config).unwrap();

    //Generating the shared secret
    let s_key = create_shared_secret(key, user_public_key).unwrap();

    //decrypting file with iv,key
    let unencrypted = decrypt(Cipher::chacha20(), s_key.as_bytes(), Some(&iv), &encrypted);

    //writing file out
    let fileout = Path::new(&out_file_holder);
    let mut decrypted_file_path = File::create(fileout).expect("Unable to write file to disk");
    decrypted_file_path
        .write_all(&unencrypted.unwrap())
        .expect("unable to write encrypted file");
}

//Loads environmental variables for access to the S3 instances
pub fn load_aws_credentials() -> Credentials {
    //loads aws creds from Bash enviromental variables
    let aws_access =
        var("AWS_ACCESS_KEY_ID").expect("Must specify $AWS_ACCESS_KEY_ID in your environment");
    let aws_secret = var("AWS_SECRET_ACCESS_KEY")
        .expect("Must specify $AWS_SECRET_ACCESS_KEY in your environment");

    //returns credtials type for rust-s3
    Credentials::new(Some(aws_access), Some(aws_secret), None, None)
}

//Sends file to AWS
pub fn create_file_on_aws(
    user: &String,
    file_name: &String,
    file: Vec<u8>,
    region_input: &String,
    bucket_name: &String,
) -> Result<(), S3Error> {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string += "/";
    user_sha_string += &file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials).unwrap();

    add_users_folder(&user, &region_input, &bucket_name)?;

    let (_, code) = bucket.put_object(&user_sha_string, &file, "text/plain").unwrap();

    if code != 200 {
        println!(
            "Sorry there was an error putting this file in the S3 HTTP code: {}",
            code
        );

        Err(S3Error::from_kind(EK::Msg("Error: Non-200 response code while uploading file".to_string())))
    } else {
        Ok(())
    }
}

//Adds the users folder if it doesn't exist
//SHA512 to hide emails
pub fn add_users_folder(user: &String, region_input: &String, bucket_name: &String) -> Result<(), S3Error> {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string += "/";

    //using a blank string to add a folder
    let blank = String::new();

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials)?;

    let (_, code) = bucket.put_object(&user_sha_string, &blank.as_bytes(), "text/plain")?;
    
    Ok(())
}

//List files in queue
pub fn list_files_in_folder(
    user: &String,
    region_input: &String,
    bucket_name: &String,
    listing: bool,
) -> Result<Vec<String>, S3Error> {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string += "/";

    let mut output_list: Vec<String> = Vec::new();

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials)?;

    let user_name_result = match bucket.list(&user_sha_string, Some("/")) {
        Ok(x) => (x),
        Err(e) => {
            add_users_folder(user, region_input, bucket_name)?;
            println!(
                "Your username wasn't found on the S3, so I added it for you :), now have a friend send you a file\n\tError: {}",
                e
            );
            exit(2);
        }
    };

    let code = user_name_result[0].1;
    let bucket_list_result = &user_name_result[0].clone();
    let mut list = bucket_list_result.0.clone();

    if code != 200 {
        println!("AWS error: HTTP code: {}", code);
         Err(S3Error::from_kind(EK::Msg("Error: Non-200 response code while trying to get files".to_string())))
    } else {

        //checking if there is a folder with the specified username
        if list.contents.len() == 0 {
            println!("Error: the folder was not accessible, or was deleted");
        } else {
            list.contents.remove(0); //removing the first result which is the folder
            if code != 200 {
                println!(
                    "Sorry there was an error adding this user folder to the S3 HTTP code: {}",
                    code
                );
            } else {
                if list.contents.len() > 0 {
                    for (file_count, file_name) in list.contents.iter().enumerate() {
                        //for each file print the file name
                        let paths: Vec<&str> = file_name.key.split("/").collect(); //file name has folder name on top of it
                        output_list.push(paths[1].to_string());
                        if listing == true {
                            println!("{}) {}", file_count, paths[1]); //will only every be one folder deep by design
                        }
                    }
                }
            }
        }
        Ok(output_list)
    }
}

//Stringify Hex to hide users email
pub fn vec_to_hex_string(hex_vec: Vec<u8>) -> String {
    //formats a vector of u8s to padded hex string for storing username
    let mut out_string = String::new();

    for i in hex_vec {
        out_string += &format!("{:01$X}", i, 2);
    }
    out_string
}

//Deletes specified file on AWS
pub fn aws_file_deleter(
    user: &String,
    region_input: &String,
    bucket_name: &String,
    file_name: &String,
) -> Result<(), S3Error> {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string += "/";
    user_sha_string += &file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials)?;

    let out = bucket.delete_object(&user_sha_string);

    match out {
        Ok(code) => {
            if code.1 != 204 {
                Err(S3Error::from_kind(EK::Msg("Error: Non-204 response code for file deletion".to_string()))) 
            } else {
                Ok(())
            }
        }
        Err(_e) => {
             Err(S3Error::from_kind(EK::Msg("Error: Deletion failed".to_string())))
        }
    }
}

//Receives a file from the AWS
pub fn aws_file_getter(
    file_name: &String,
    username: &String,
    file_region: &String,
    bucket_name: &String,
) -> Result<Vec<u8>, S3Error> {
    let credentials = load_aws_credentials();

    let region = file_region.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials)?;

    let user_sha = sha::sha512(username.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let user_sha_string = vec_to_hex_string(user_sha_vec);

    let (file, code) = bucket.get_object(&(user_sha_string + "/" + &file_name))?;

    if code == 200 {
        Ok(file)
    } else {
         Err(S3Error::from_kind(EK::Msg("Error: Non-200 response code while getting file".to_string())))
    }
}

pub fn aws_file_getter_withoutsha(
    file_name: &String,
    username: &String,
    file_region: &String,
    bucket_name: &String,
) -> Result<Vec<u8>, S3Error> {
    let credentials = load_aws_credentials();

    let region = file_region.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials)?;

    let (file, code) = bucket.get_object(&(format!("{}/{}", username, file_name)))?;

    if code == 200 {
        Ok(file)
    } else {
         Err(S3Error::from_kind(EK::Msg("Error: Non-200 response code while getting file".to_string())))
    }
}

//Gets receives public key, Encrypts, and sends file
pub fn send_file(
    sending_file_path: &String,
    to_user: &String,
    pconfig: &Config,
    encrypt: Encryption,
) -> Result<(), S3Error> {
    println!("\nSending file: {}", sending_file_path);

    //encrypting and sending a file to the AWS
    //Encrypting
    let out_blob: FileBlob = match encrypt {
        Encryption::AES => aes_encrypter(
            sending_file_path.to_owned(),
            pconfig.to_owned(),
            to_user.to_owned(),
        ),
        Encryption::Chacha => chacha_encrypter(
            sending_file_path.to_owned(),
            pconfig.to_owned(),
            to_user.to_owned(),
        ),
    };

    //serializing to sent to AWS (need Vec<u8>)
    let file_to_aws = to_string(&out_blob).unwrap();

    let file_name_list: Vec<&str> = sending_file_path.split("/").collect();
    let file_name_st = file_name_list[file_name_list.len() - 1].to_string();

    //sending to s3
    create_file_on_aws(
        to_user,
        &file_name_st,
        file_to_aws.as_bytes().to_vec(),
        &pconfig.file_store_region,
        &pconfig.file_store,
    ) 
}

//Gets file from AWS and decrypts
pub fn get_file(
    file_name_wrapper: Option<String>,
    output_directory: &String,
    all: bool,
    pconfig: &Config,
    delete_file: bool,
    encrypt: Encryption,
) {
    let file_list: Vec<String> = list_files_in_folder(
        &pconfig.email,
        &pconfig.file_store_region,
        &pconfig.file_store,
        false,
    ).unwrap();

    if file_list.len() == 0 {
        println!("No files to get! Why not send a file?");
        exit(0);
    }

    if all == true {
        println!("Getting all files\n");
        for i in file_list.iter() {
            //testing receiving file and decryption
            //first get file from AWS store

            let file_from_aws = aws_file_getter(
                i,
                &pconfig.email,
                &pconfig.file_store_region,
                &pconfig.file_store,
            ).unwrap();

            //removing file from AWS
            if delete_file {
                aws_file_deleter(
                    &pconfig.email,
                    &pconfig.file_store_region,
                    &pconfig.file_store,
                    i,
                ).unwrap(); //create an option to keep this
            }

            //deserializing
            let out: FileBlob = from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();

            //decrypting
            let output_file_directory;

            if Path::new(output_directory).is_dir() {
                output_file_directory = output_directory.to_string() + "/" + i;
            } else {
                output_file_directory = output_directory.to_string();
            }
            match encrypt {
                Encryption::AES => aes_decrypter(output_file_directory, out, pconfig.to_owned()),
                Encryption::Chacha => {
                    chacha_decrypter(output_file_directory, out, pconfig.to_owned())
                }
            }
        }
    } else {
        for (c, f) in file_list.iter().enumerate() {
            println!("{}) {}", c, f);
        }

        let file_name = match file_name_wrapper {
            Some(file_name) => file_name,
            None => {
                let mut file_holder = String::new();
                print!("Select index of file: ");
                stdout().flush().expect("Unable to flush stdout");
                stdin()
                    .read_line(&mut file_holder)
                    .expect("Failed reading user input");
                file_holder = file_holder.trim().to_string();
                file_holder.pop();
                let file_out = &file_list[file_holder
                    .parse::<usize>()
                    .expect("Cannot convert the index, try again")];
                file_out.to_owned()
            }
        };

        println!("\nGetting file: {}", file_name);

        //first get file from AWS store
        let file_from_aws = aws_file_getter(
            &file_name,
            &pconfig.email,
            &pconfig.file_store_region,
            &pconfig.file_store,
        ).unwrap();

        //removing file from AWS
        if delete_file {
            aws_file_deleter(
                &pconfig.email,
                &pconfig.file_store_region,
                &pconfig.file_store,
                &file_name,
            ).unwrap(); //create an option to keep this
        }

        //deserializing
        let out: FileBlob = from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();

        //decrypting
        let output_file_directory;

        if Path::new(output_directory).is_dir() {
            output_file_directory = output_directory.to_string() + "/" + &file_name;
        } else {
            output_file_directory = output_directory.to_string();
        }

        match encrypt {
            Encryption::AES => aes_decrypter(output_file_directory, out, pconfig.to_owned()),
            Encryption::Chacha => chacha_decrypter(output_file_directory, out, pconfig.to_owned()),
        }
    }
}
