extern crate clap;
extern crate openssl;
extern crate rand;
extern crate s3;
extern crate serde;
//#[macro_use] extern crate serde_derive;
extern crate toml;

use openssl::*;
use std::fs::{File, remove_file};
use std::os::unix::fs::PermissionsExt;
use std::io::{Write, stdin, stdout};
use std::io::prelude::*;
use toml::{to_string, from_str};
use std::env::{home_dir, var};
use std::str;
use std::process::exit;
use rand::Rng;
use s3::credentials::Credentials;
use s3::bucket::Bucket;

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct Config {
    pub email: String,
    pub private_key: String,
    pub public_key: String,
    pub file_store: String,
    pub file_store_region: String,
    pub public_key_store: String,
    pub public_key_store_region: String,
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct FileBlob {
    pub file: Vec<u8>,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

pub fn create_config() {
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");
    let postio_config_file_path = postio_dir.to_owned().join("config");

    let mut private_key_path = String::new();
    let mut public_key_path = String::new();

    print!("Do you have 4096-bit RSA pub/private keys in PEM format? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    let mut key_maybe = String::new();
    stdin().read_line(&mut key_maybe).expect("Something went wrong capturing user input");;
    key_maybe.trim().to_uppercase();
    key_maybe.pop();

    if key_maybe == "Y" {
        print!("Full path to your public key: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut public_key_path).expect("Something went wrong capturing user input");;
        public_key_path.trim();
        public_key_path.pop();

        print!("Full path to your private key: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut private_key_path).expect("Something went wrong capturing user input");;
        private_key_path.trim();
        private_key_path.pop();

    }

    else if key_maybe == "N" {

        let keys = openssl::rsa::Rsa::generate(4096).unwrap();
        let privy = &keys.private_key_to_pem().unwrap();
       
        let private_key_dir = postio_dir.to_owned().join("private_key.pem");
        let mut sender_priv = File::create(private_key_dir).unwrap();
            sender_priv.write_all(&privy).expect("Unable to write private key");
                let sender_priv_meta = sender_priv.metadata().expect("Unable to get metadata on file");
                    let mut sender_priv_perms = sender_priv_meta.permissions();
                        sender_priv_perms.set_mode(700);

        let pubby = &keys.public_key_to_pem().unwrap();
        let mut sender_pub = File::create(postio_dir.to_owned().join("public_key.pem").as_path()).unwrap();
            sender_pub.write_all(&pubby).expect("Unable to create public key");

        private_key_path =  home_dir.to_owned().join(".postio/private_key.pem").as_path().to_str().unwrap().to_owned();
        public_key_path = home_dir.to_owned().join(".postio/public_key.pem").as_path().to_str().unwrap().to_owned();
    }

    else {
        println!("Yeah it was a yes or no question... [Y/N]");
        exit(1);
    }

    let mut user_email = String::new();
    print!("Please enter the email address you wish to use: ");
    stdout().flush().expect("Unable to flush stdout");  
    stdin().read_line(&mut user_email).expect("Something went wrong capturing user input");
    user_email.trim();
    user_email.pop();

    let mut postio_file_store_answer = String::new();
    let mut postio_file_store = String::new();
    let mut postio_file_store_region = String::new();

    print!("Do you have an AWS S3 store setup for files? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    stdin().read_line(&mut postio_file_store_answer).expect("Something went wrong capturing user input");
    postio_file_store_answer.trim();
    postio_file_store_answer.pop();

    if postio_file_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 store name: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut postio_file_store).expect("Something went wrong capturing user input");
        postio_file_store.trim();
        postio_file_store.pop();

        print!("S3 store region: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut postio_file_store_region).expect("Something went wrong capturing user input");
        postio_file_store_region.trim();
        postio_file_store_region.pop();
    }

    else if  postio_file_store_answer.to_uppercase() == "N".to_string() {
        postio_file_store = "postio".to_string();
        postio_file_store_region = "eu-west-2".to_string();
    }

    else {
        println!("Expecting Y or N...");
        exit(1);
    }

    let mut postio_key_store_answer = String::new();
    let mut postio_key_store = String::new();
    let mut postio_key_store_region = String::new();

    print!("Do you have an AWS S3 store setup for public keys? [Y/N]: ");
    stdout().flush().expect("Unable to flush stdout");
    stdin().read_line(&mut postio_key_store_answer).expect("Failed reading user input");
    postio_key_store_answer.trim();
    postio_key_store_answer.pop();

    if postio_key_store_answer.to_uppercase() == "Y".to_string() {
        print!("Amazon S3 public key store name: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut postio_key_store).expect("Failed reading user input");
        postio_key_store.trim();
        postio_key_store.pop();

        print!("S3 store region: ");
        stdout().flush().expect("Unable to flush stdout");
        stdin().read_line(&mut postio_key_store_region).expect("Failed reading user input");
        postio_key_store_region.trim();
        postio_key_store_region.pop();
    }

    else if postio_key_store_answer.to_uppercase() == "N".to_string() {
        postio_key_store = "postio-keys".to_string();
        postio_key_store_region = "eu-central-1".to_string();
    }

    else {
        println!("Expecting Y or N...");
        exit(1);
    }

    let postio_config_content: Config = Config{email:user_email, private_key: private_key_path, public_key: public_key_path, file_store: postio_file_store, file_store_region: postio_file_store_region, public_key_store: postio_key_store, public_key_store_region: postio_key_store_region};

    //using new config to send public key to keystore
    let user_name = &postio_config_content.email;
    let pub_key_reg = &postio_config_content.public_key_store_region;
    let pub_key_bucket = &postio_config_content.public_key_store;
    
    //adding user to database
    add_users_folder(user_name, pub_key_reg, pub_key_bucket);
    
    //opening public key
    let mut pub_key = Vec::new();
    let mut pub_key_file = File::open(postio_config_content.public_key.to_owned()).unwrap();
        pub_key_file.read_to_end(&mut pub_key).expect("Unable to read public key");
    
    //sending public key
    create_file_on_aws(&user_name, &"public_key".to_string(), pub_key, &pub_key_reg, &pub_key_bucket);

    //serializing config file
    let postio = to_string(&postio_config_content).unwrap();

    //writing config file to ~/.postio
    let mut postio_config_file = File::create(postio_config_file_path).unwrap();
        postio_config_file.write_all(&postio.as_bytes()).expect("Cannot write postio config file");
}

pub fn read_config(config_file_path: &String) -> Config {
    //opening and deserializing config
    let mut config_file_holder = match File::open(&config_file_path) {
        Ok(x) => x,
        Err(e) => {println!("Error! Couldn't open file: {}",e); exit(1);},
    };
    let mut config_file = String::new();
        config_file_holder.read_to_string(&mut config_file).unwrap();

    let postio_config = from_str(&config_file);

    //getting config file 
    match postio_config {
        Err(e) => {
            let mut delete_answer = String::new();
            print!("Error in your config file, please check your settings!\n\tWould you like to delete the config file? [Y/N]: ");
            stdout().flush().expect("Unable to flush output, that's bad");
            stdin().read_line(&mut delete_answer).expect("User input failed..Sorry");
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
            return config;
        }
    }
}

pub fn aes_encrypter(file_path: String, pconfig: Config, to_user: String) -> FileBlob {
    let mut iv = Vec::new();
    let mut key = Vec::new();
    let mut rng = rand::thread_rng(); 
    
    //randomizing IV (16 bytes)
    for _ in 0..16 {
        iv.push(rng.gen::<u8>());
    }
    //randomizing symmetic key (32 bytes)
    for _ in 0..32 {
        key.push(rng.gen::<u8>());
    }

    //opening file to encrypt
    let mut unencrypted_file = File::open(file_path).unwrap();
    let mut file_buffer = Vec::new();
        unencrypted_file.read_to_end(&mut file_buffer).expect("Unable to read file");

    let encrypted_file = openssl::symm::encrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &file_buffer);
    
    //encrypying IV,Key with public key of receiver
    let (encrypted_iv, encrypted_key) = rsa_encrypter(pconfig, to_user, iv, key);

    //putting file, IV, and symmetic key, together into a blob and sending to AWS S3
    let file_blob_for_aws: FileBlob = FileBlob{file: encrypted_file.unwrap(), key: encrypted_key, iv: encrypted_iv};

    //return blob
    file_blob_for_aws
}

pub fn aes_decrypter(out_file_path: String, file_from_aws: FileBlob, postio_config: Config) {
    //disecting fileblob from AWS
    let encrypted = file_from_aws.file;
    let encrypted_key = file_from_aws.key;
    let encrypted_iv = file_from_aws.iv;

    //decrypting IV,Key with private certificates
    let (iv, key) = rsa_decrypter(postio_config.private_key, encrypted_iv, encrypted_key);

    //decrypting file with iv,key
    let unencrypted =  openssl::symm::decrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &encrypted);

    //writing file out
    let mut decrypted_file_path = File::create(out_file_path).unwrap();
        decrypted_file_path.write_all(&unencrypted.unwrap()).expect("unable to write encrypted file");
}

pub fn rsa_encrypter(pconfig: Config, to_user: String, unencrypted_iv: Vec<u8>, unencrypted_key: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //setting output buffer to write encrypted files to
    let mut enc_buffer_iv = [0u8;512];  //16 bytes
    let mut enc_buffer_key = [0u8;512]; //32 bytes

    //getting public key of receiver
    let public_key = aws_file_getter(&"public_key".to_string(), to_user, pconfig.public_key_store_region, pconfig.public_key_store);

    //opening your private key
    let mut pv_key = File::open(pconfig.private_key).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
        pv_key.read_to_end(&mut private_key).expect("Unable to read Private key (for encryption)");

    //enabling keys with openssl for RSA decryption
    let mut _keys = openssl::rsa::Rsa::private_key_from_pem(&private_key).unwrap();
    _keys =  openssl::rsa::Rsa::public_key_from_pem(&public_key).unwrap();

    //encrypting IV,Keys
    let _iv_out = _keys.public_encrypt(&unencrypted_iv, &mut enc_buffer_iv, openssl::rsa::PKCS1_OAEP_PADDING);
    let _key_out = _keys.public_encrypt(&unencrypted_key, &mut enc_buffer_key, openssl::rsa::PKCS1_OAEP_PADDING);

    (enc_buffer_iv.to_vec(), enc_buffer_key.to_vec())
}

pub fn rsa_decrypter(private_key_path: String, iv_to_decrypt: Vec<u8>, key_to_decrypt: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //opening your private key to decrypt IV,Key
    let mut private_key_file = File::open(private_key_path).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
        private_key_file.read_to_end(&mut private_key).expect("Not able to read private key!");
    
    let keys = openssl::rsa::Rsa::private_key_from_pem(&private_key).unwrap();

    //buffer for decrypted iv,keys
    let mut decrypted_iv = [0u8;512]; //16
    let mut decrypted_key = [0u8;512]; //32

    //decrypting and truncated buffer to original lengths
    let _file_out = keys.private_decrypt(&iv_to_decrypt, &mut decrypted_iv, openssl::rsa::PKCS1_OAEP_PADDING);
        let decrypted_iv_trunct: Vec<u8> = decrypted_iv[0..16].to_vec();

    let _file_out = keys.private_decrypt(&key_to_decrypt, &mut decrypted_key, openssl::rsa::PKCS1_OAEP_PADDING);
        let decrypted_key_trunct: Vec<u8> = decrypted_key[0..32].to_vec();

    (decrypted_iv_trunct, decrypted_key_trunct)
}

pub fn load_aws_credentials() -> Credentials {
    //loads aws creds from Bash enviromental variables
    let aws_access = var("AWS_ACCESS_KEY_ID").expect("Must specify AWS_ACCESS_KEY_ID");
    let aws_secret = var("AWS_SECRET_ACCESS_KEY").expect("Must specify AWS_SECRET_ACCESS_KEY");

    //returns credtials type for rust-s3
    Credentials::new(&aws_access, &aws_secret, None)
}

pub fn create_file_on_aws(user: &String, file_name: &String, file: Vec<u8>, region_input: &String, bucket_name: &String) {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
        user_sha_string+="/";
            user_sha_string+=&file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials);

    add_users_folder(&user, &region_input, &bucket_name);

    let (_, code) = bucket.put(&user_sha_string, &file, "text/plain").unwrap();

    if  code != 200 {
        println!("Sorry there was an error putting this file in the S3 HTTP code: {}", code);
    }
}

pub fn add_users_folder(user: &String, region_input: &String, bucket_name: &String) {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    //using a blank string to add a folder
    let blank = String::new();

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials);

    let response = bucket.list(&user_sha_string, Some(""));
    
    match response {
        Ok(_x) => println!("\nUser directory found!\n"),
        Err(_e) => {let (_, _code) = bucket.put(&user_sha_string, &blank.as_bytes(), "text/plain").unwrap();},
    }
}

pub fn list_files_in_folder(user: &String, region_input: &String, bucket_name: &String, listing: bool) -> Vec<String> {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    let mut output_list: Vec<String> = Vec::new();

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials);

    let user_name_result = match bucket.list(&user_sha_string, Some("/")) {
        Ok(x) => (x),
        Err(e) => {
            add_users_folder(user, region_input, bucket_name);
            println!("Your username wasn't found on the S3, so I added it for you :), now have a friend send you a file\n\tError: {}", e);
            exit(2);
        }
    };

    let code = user_name_result[0].1;
    let bucket_list_result = &user_name_result[0].clone();
    let mut list = bucket_list_result.0.clone();
    
    if code != 200 {
        println!("AWS error: HTTP code: {}", code);
    }
    
    //checking if there is a folder with the specified username
    if list.contents.len() == 0 {
        println!("Error: the folder was not accessible, or was deleted");
    }

    else {
        list.contents.remove(0); //removing the first result which is the folder
        if code != 200 { 
            println!("Sorry there was an error adding this user folder to the S3 HTTP code: {}", code);
        }
    
        else {
            if list.contents.len() == 0 { //after we remove the first if there none, no files
                println!("No files to get!");
            }
            else {
                for (file_count, file_name) in list.contents.iter().enumerate() { //for each file print the file name 
                    let paths: Vec<&str> = file_name.key.split("/").collect(); //file name has folder name on top of it                            
                    output_list.push(paths[1].to_string());
                    if listing == true {
                        println!("{}) {}", file_count, paths[1]); //will only every be one folder deep by design
                    }
                }
            }
        }
    }

    output_list
}

pub fn vec_to_hex_string(hex_vec: Vec<u8>) -> String {
    //formats a vector of u8s to padded hex string for storing username
    let mut out_string = String::new();

    for i in hex_vec {
        out_string += &format!("{:01$X}", i, 2);
    }

    out_string
}

pub fn aws_file_deleter(user: String, region_input: String, bucket_name: String, file_name: &String) {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
        user_sha_string+="/";
            user_sha_string+=&file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials);

    let out = bucket.delete(&user_sha_string);

    match out {
        Ok(code) => {
            if code.1 != 204 {
                println!("Deletion of file failed! You'll want to check your bucket settings most likely: HTTP code: {}", code.1);
                exit(1);
            }
        },
        Err(e) => {
                println!("Deletion of file failed! {}", e);
                exit(1);
        }
    }
}

pub fn aws_file_getter(file_name: &String, username: String, file_region: String, bucket_name: String) -> Vec<u8> {
    let credentials = load_aws_credentials();

    let region = file_region.parse().unwrap();

    let bucket = Bucket::new(&bucket_name, region, credentials);

    let user_sha = sha::sha512(username.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let user_sha_string = vec_to_hex_string(user_sha_vec);
    
    let (file, code) = bucket.get(&(user_sha_string+"/"+&file_name)).unwrap();

    if code == 200 {
        return file;
    }

    else {
        println!("Getting the file failed! HTTP: {}", code);
        exit(1);
    }
}

pub fn send_file(sending_file_path: &String, to_user: &String, pconfig: &Config) {
    println!("Sending files:\n");

    //encrypting and sending a file to the AWS
    //Encrypting
    let out_blob: FileBlob = aes_encrypter(sending_file_path.to_owned(), pconfig.to_owned(), to_user.to_owned());

    //serializing to sent to AWS (need Vec<u8>) 
    let file_to_aws = to_string(&out_blob).unwrap();

    let file_name_list: Vec<&str> = sending_file_path.split("/").collect();
    let file_name_st = file_name_list[file_name_list.len()-1].to_string();

    //sending to s3
    create_file_on_aws(to_user, &file_name_st, file_to_aws.as_bytes().to_vec(), &pconfig.file_store_region, &pconfig.file_store);
}

pub fn get_file(file_name: &String, output_directory: &String, all: bool, pconfig: &Config, delete_file: bool) {
    println!("Getting files:\n");

        if all == true {
            let file_list: Vec<String> =  list_files_in_folder(&pconfig.email, &pconfig.file_store_region, &pconfig.file_store, false);
            
            for i in file_list.iter() {
                //testing receiving file and decryption
                //first get file from AWS store
            
                let file_from_aws = aws_file_getter(i, pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned());

                //removing file from AWS
                if delete_file {}
                aws_file_deleter(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), i); //create an option to keep this
                
                //deserializing
                let out: FileBlob = from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();
                
                //decrypting
                let output_file_directory = output_directory.to_string()+"/"+i;
                aes_decrypter(output_file_directory, out, pconfig.to_owned());                 
            }
        }

        else {
                //first get file from AWS store
                let file_from_aws = aws_file_getter(file_name, pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned());

                //removing file from AWS
                if delete_file {
                    aws_file_deleter(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), file_name); //create an option to keep this
                }

                //deserializing
                let out: FileBlob = from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();
                
                //decrypting
                let output_file_directory = output_directory.to_string()+"/"+file_name;
                aes_decrypter(output_file_directory, out, pconfig.to_owned()); 
        }

}