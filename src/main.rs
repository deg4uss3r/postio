#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate openssl;
extern crate serde;
extern crate rand;
extern crate s3;

use openssl::*;
use std::env::args;
use std::fs::{File, create_dir, Permissions, remove_file};
use std::os::unix::fs::PermissionsExt;
use std::io::{Write, stdin, stdout};
use std::io::prelude::*;
use toml::*;
use std::env::{home_dir};
use std::path::{PathBuf, Path};
use std::env;
use std::str;
use std::process::exit;
use rand::Rng;
use s3::credentials::Credentials;
use s3::bucket::Bucket;

//everything works! 
//
//need to: 
//  Clean up code!
//  create serde struct for file, key, iv to store in S3 :)
//  serialize on send 
//  deserialize on receive 
//  add S3 instance to postio config
//  start up S3 for files
//  start up S3 for IVs/Keys
//  create file senders
//  create file receivers
//  create file listers
//  create folder creaters
//  create file deleters
//  finally create server host on Digital Ocean to interface with the S3
//
//  arn:aws:s3:::postio eu-west-2

#[derive(Serialize,Deserialize,Debug,Clone)]
struct Config {
    email: String,
    private_key: String,
    public_key: String,
    file_store: String,
    file_store_region: String,
    public_key_store: String,
    public_key_store_region: String,
}

#[derive(Serialize,Deserialize,Debug,Clone)]
struct FileBlob {
    file: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
}

fn check_for_config() -> (bool, bool) {
    //config location will be ~/.postio/config
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");
    let postio_config_file = postio_dir.to_owned().join("config");
   
    let mut rtn_tuple = (false, false); 

    if postio_dir.is_dir() {
        rtn_tuple = (true, false);
        if postio_config_file.is_file() {
            rtn_tuple = (true, true);
        }
        else {
            rtn_tuple = (true, false);
        }
    }
    else {
        rtn_tuple = (false, false);
    }

    rtn_tuple
}

fn create_config() {
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");
    let postio_config_file_path = postio_dir.to_owned().join("config");

    let mut private_key_path = String::new();
    let mut public_key_path = String::new();

    print!("Do you have 4096-bit RSA pub/private keys in PEM format? [Y/N]: ");
    stdout().flush();
    let mut key_maybe = String::new();
    stdin().read_line(&mut key_maybe);
    key_maybe.trim().to_uppercase();
    key_maybe.pop();

    if key_maybe == "Y" {
        print!("Full path to your public key: ");
        stdout().flush();
        stdin().read_line(&mut public_key_path);
        public_key_path.trim();
        public_key_path.pop();

        print!("Full path to your private key: ");
        stdout().flush();
        stdin().read_line(&mut private_key_path);
        private_key_path.trim();
        private_key_path.pop();

    }

    else if key_maybe == "N" {

        let keys = openssl::rsa::Rsa::generate(4096).unwrap();
        let privy = &keys.private_key_to_pem().unwrap();
       
        let private_key_dir = postio_dir.to_owned().join("private_key.pem");
        let mut sender_priv = File::create(private_key_dir).unwrap();
            sender_priv.write_all(&privy);

        let pubby = &keys.public_key_to_pem().unwrap();
        let mut sender_pub = File::create(postio_dir.to_owned().join("public_key.pem").as_path()).unwrap();
            sender_pub.write_all(&pubby);

        private_key_path =  home_dir.to_owned().join(".postio/private_key.pem").as_path().to_str().unwrap().to_owned();
        public_key_path = home_dir.to_owned().join(".postio/public_key.pem").as_path().to_str().unwrap().to_owned();
    }

    else {
        println!("Yeah it was a yes or no question... [Y/N]");
        exit(1);
    }

    let mut user_email = String::new();
    print!("Please enter the email address you wish to use: ");
    stdout().flush();  
    stdin().read_line(&mut user_email);
    user_email.trim();
    user_email.pop();

    let mut postio_file_store_answer = String::new();
    let mut postio_file_store = String::new();
    let mut postio_file_store_region = String::new();

    print!("Do you have an AWS S3 store setup for files? [Y/N]: ");
    stdout().flush();
    stdin().read_line(&mut postio_file_store_answer);
    postio_file_store_answer.trim();
    postio_file_store_answer.pop();

    if postio_file_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 store name: ");
        stdout().flush();
        stdin().read_line(&mut postio_file_store);
        postio_file_store.trim();
        postio_file_store.pop();

        print!("S3 store region: ");
        stdout().flush();
        stdin().read_line(&mut postio_file_store_region);
        postio_file_store_region.trim();
        postio_file_store_region.pop();
    }

    else {
        postio_file_store = "postio".to_string();
        postio_file_store_region = "eu-west-2".to_string();
    }

    let mut postio_key_store_answer = String::new();
    let mut postio_key_store = String::new();
    let mut postio_key_store_region = String::new();

    print!("Do you have an AWS S3 store setup for public keys? [Y/N]: ");
    stdout().flush();
    stdin().read_line(&mut postio_key_store_answer);
    postio_key_store_answer.trim();
    postio_key_store_answer.pop();

    if postio_key_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 public key store name: ");
        stdout().flush();
        stdin().read_line(&mut postio_key_store);
        postio_key_store.trim();
        postio_key_store.pop();

        print!("S3 store region: ");
        stdout().flush();
        stdin().read_line(&mut postio_key_store_region);
        postio_key_store.trim();
        postio_key_store.pop();
    }

    else {
        postio_key_store = "postio-keys".to_string();
        postio_key_store_region = "eu-central-1".to_string();
    }

    let postio_config_content: Config = Config{email:user_email, private_key: private_key_path, public_key: public_key_path, file_store: postio_file_store, file_store_region: postio_file_store_region, public_key_store: postio_key_store, public_key_store_region: postio_key_store_region};

    let postio = toml::to_string(&postio_config_content).unwrap();

    let mut postio_config_file = File::create(postio_config_file_path).unwrap();
    postio_config_file.write_all(&postio.as_bytes());
}

fn create_postio_dir() {
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");

    create_dir(postio_dir.to_owned());
}

fn read_config() -> Config {
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");
    let config_file_path = postio_dir.to_owned().join("config");

    let mut config_file_holder = File::open(&config_file_path).unwrap();
    let mut config_file = String::new();
    config_file_holder.read_to_string(&mut config_file).unwrap();

    let postio_config = toml::from_str(&config_file);

        match postio_config {
            Err(e) => {
                let mut delete_answer = String::new();
                print!("Error in your config file, please check your settings!\n\tWould you like to delete the config file? [Y/N]: ");
                stdout().flush();
                stdin().read_line(&mut delete_answer);
                delete_answer.trim();
                delete_answer.pop();

                if delete_answer.to_uppercase() == "Y".to_string() {
                    remove_file(&config_file_path).unwrap();
                    println!("Config file deleted, run the program again to set it up!");
                    exit(99);
                }

                else {
                    println!("File not deleted please check your configurations: {}", e);
                    exit(1);
                }
            },
            Ok(config) => {
                let mut pconfig: Config = config;
                let user_name: String = pconfig.email.to_owned();
                let pub_key_reg: String = pconfig.public_key_store_region.to_owned();
                let pub_key_bucket: String = pconfig.public_key_store.to_owned();

                add_users_folder(user_name.to_owned(), pub_key_reg.to_owned(), pub_key_bucket.to_owned());

                let mut pub_key = Vec::new();
                let mut pub_key_file = File::open(pconfig.public_key.to_owned()).unwrap();
                    pub_key_file.read_to_end(&mut pub_key);

                create_file_on_aws(user_name.to_owned(), "public_key".to_string(), pub_key, pub_key_reg.to_owned(), pub_key_bucket.to_owned());

                return pconfig;
            }
        }
}

fn aes_encrypter(file_path: String, pconfig: Config) -> FileBlob {
    let mut iv = Vec::new();
    let mut key = Vec::new();

    let mut rng = rand::thread_rng(); 

    for _ in 0..16 {
        iv.push(rng.gen::<u8>());
    }

    for _ in 0..32 {
        key.push(rng.gen::<u8>());
    }

    let mut unencrypted_file = File::open(file_path).unwrap();
    let mut file_buffer = Vec::new();
    unencrypted_file.read_to_end(&mut file_buffer);

    let encrypted_file = openssl::symm::encrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &file_buffer);
    
    let (encrypted_key, encrypted_iv) = rsa_encrypter(pconfig, iv, key);

    let fileBlobForAWS: FileBlob = FileBlob{file: encrypted_file.unwrap(), key: encrypted_key, iv: encrypted_iv};

    fileBlobForAWS
}

fn aes_decrypter(out_file_path: String, fileFromAWS: FileBlob, postio_config: Config) {
    let encrypted = fileFromAWS.file;
    let encrypted_key = fileFromAWS.key;
    let encrypted_iv = fileFromAWS.iv;


    let (key, iv) = rsa_decrypter(postio_config.private_key, encrypted_iv, encrypted_key);

    let unencrypted =  openssl::symm::decrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &encrypted);

    let mut decrypted_file_path = File::create(out_file_path).unwrap();
    decrypted_file_path.write_all(&unencrypted.unwrap());
}

fn rsa_encrypter(pconfig: Config, unencrypted_iv: Vec<u8>, unencrypted_key: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut enc_buffer_iv = [0u8;512];  //16 bytes
    let mut enc_buffer_key = [0u8;512]; //32 bytes

    let user_sha = sha::sha512(pconfig.email.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/public_key";

    let public_key = aws_file_getter("public_key".to_string(), pconfig.email, pconfig.public_key_store_region, pconfig.public_key_store);

    let mut keys =  openssl::rsa::Rsa::public_key_from_pem(&public_key).unwrap(); 

    let iv_out = keys.public_encrypt(&unencrypted_iv, &mut enc_buffer_iv, openssl::rsa::PKCS1_OAEP_PADDING);
    let key_out = keys.public_encrypt(&unencrypted_key, &mut enc_buffer_key, openssl::rsa::PKCS1_OAEP_PADDING);

    (enc_buffer_iv.to_vec(), enc_buffer_key.to_vec())
}

fn rsa_decrypter(private_key_path: String, iv_to_decrypt: Vec<u8>, key_to_decrypt: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut private_key_file = File::open(private_key_path).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
    private_key_file.read_to_end(&mut private_key);
    
    let keys = openssl::rsa::Rsa::private_key_from_pem(&private_key).unwrap();

    let mut decrypted_iv = [0u8;512]; //16
    let mut decrypted_key = [0u8;512]; //32

    let file_out = keys.private_decrypt(&iv_to_decrypt, &mut decrypted_iv, openssl::rsa::PKCS1_OAEP_PADDING);
    let decrypted_iv_trunct: Vec<u8> = decrypted_iv[0..16].to_vec();

    let file_out = keys.private_decrypt(&key_to_decrypt, &mut decrypted_key, openssl::rsa::PKCS1_OAEP_PADDING);
    let decrypted_key_trunct: Vec<u8> = decrypted_key[0..32].to_vec();

    (decrypted_iv_trunct, decrypted_key_trunct)
}


fn open_file(file_path: String) -> Vec<u8> {
    let mut out_file: Vec<u8> = Vec::new();
    let mut file = File::open(file_path).expect("Problems with the file path you gave");

    file.read_to_end(&mut out_file).expect("Cannot read file");

    out_file
}

fn load_aws_credentials() -> Credentials {
    let aws_access = env::var("AWS_ACCESS_KEY_ID").expect("Must specify AWS_ACCESS_KEY_ID");
    let aws_secret = env::var("AWS_SECRET_ACCESS_KEY").expect("Must specify AWS_SECRET_ACCESS_KEY");

    Credentials::new(&aws_access, &aws_secret, None)
}

fn create_file_on_aws(user: String, file_name: String, file: Vec<u8>, region_input: String, bucket_name: String) {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let blank = String::new();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";
    user_sha_string+=&file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let bucket = Bucket::new(BUCKET, region, credentials);

    add_users_folder(user, region_input, bucket_name.to_owned());

    let (_, code) = bucket.put(&user_sha_string, &file, "text/plain").unwrap();

    if  code == 200 {
        println!("File transfer successfully");
    }
    else {
        println!("Sorry there was an error putting this file in the S3 HTTP code: {}", code);

    }
}

fn add_users_folder(user: String, region_input: String, bucket_name: String) {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let blank = String::new();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let mut bucket = Bucket::new(BUCKET, region, credentials);

    let response = bucket.list(&user_sha_string, Some(""));
    
    match response {
        Ok(x) => println!("User folder exists :)"),
        Err(e) => {let (_, code) = bucket.put(&user_sha_string, &blank.as_bytes(), "text/plain").unwrap();},
    }
}

fn list_files_in_folder(user: String, region_input: String, bucket_name: String) {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let blank = String::new();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let mut bucket = Bucket::new(BUCKET, region, credentials);

    let (mut list, code) = bucket.list(&user_sha_string, Some("/")).unwrap();
    
    if code != 200 {
        println!("AWS error: HTTP code: {}", code);
    }

    if list.contents.len() == 0 {
        println!("Error: Your username wasn't found, this shouldn't happen logically");
    }
    else {
        list.contents.remove(0);
        if code != 200 {
            println!("Sorry there was an error adding this user folder to the S3 HTTP code: {}", code);
        }
    
        else {
            if list.contents.len() == 0 {
                println!("No files to get!");
            }
            else {
                for (file_count, file_name) in list.contents.iter().enumerate() {
                    match file_name.key.clone() {
                        Some(b) => {
                            let mut paths: Vec<&str> = b.split("/").collect();
                            println!("{}) {}\n", file_count, paths[1]);
                        },
                        None => println!("No files exist!")
                    }
                }
            }
        }
    }
}

fn vec_to_hex_string(hex_vec: Vec<u8>) -> String {
    let mut out_string = String::new();

    for i in hex_vec {
        out_string += &format!("{:01$X}", i, 2);
    }

    out_string
}

fn aws_file_getter(file_name: String, username: String, file_region: String, bucket_name: String) -> Vec<u8> {
    let credentials = load_aws_credentials();

    let region = file_region.parse().unwrap();
    let BUCKET = &bucket_name;

    let mut bucket = Bucket::new(BUCKET, region, credentials);

    let user_sha = sha::sha512(username.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    
    let (file, code) = bucket.get(&(user_sha_string+"/"+&file_name)).unwrap();

    if code == 200 {
        return file;
    }

    else {
        println!("Getting the file failed! HTTP: {}", code);
        exit(1);
    }
}


fn main() {
        let config_results = check_for_config();

        let postio_config: Config = match config_results {
            (true, true) => read_config(),
            (true, false) => {create_config(); read_config()},
            (_, _) => {create_postio_dir(); create_config(); read_config()},
        };

        //testing encrypting and sending a file to the AWS
       //Encrypting
       let out_blob: FileBlob = aes_encrypter("./test_file".to_string(), postio_config.to_owned());
       //serializing to sent to AWS (need Vec<u8>) 
       let file_to_aws = toml::to_string(&out_blob).unwrap();
       //sending to s3
        create_file_on_aws("ricky.hosfelt@gmail.com".to_string(), "meh".to_string(), file_to_aws.as_bytes().to_vec(), postio_config.file_store_region.to_owned(), postio_config.file_store.to_owned());
}
