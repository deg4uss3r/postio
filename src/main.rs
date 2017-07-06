#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate openssl;
extern crate serde;
extern crate rand;
extern crate s3;

use openssl::*;
use std::fs::{File, create_dir, Permissions, remove_file};
use std::os::unix::fs::PermissionsExt;
use std::io::{Write, stdin, stdout};
use std::io::prelude::*;
use toml::*;
use std::env::{home_dir, args, var};
use std::path::{PathBuf, Path};
use std::str;
use std::process::exit;
use rand::Rng;
use s3::credentials::Credentials;
use s3::bucket::Bucket;

//make file deleter
//after you get a file remove it
////option to not remove it?
//loop over files in list

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
    stdin().read_line(&mut user_email).expect("Please enter a valid email address");
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
    let user_name: String = postio_config_content.email.to_owned();
    let pub_key_reg: String = postio_config_content.public_key_store_region.to_owned();
    let pub_key_bucket: String = postio_config_content.public_key_store.to_owned();
    
    //adding user to database
    add_users_folder(user_name.to_owned(), pub_key_reg.to_owned(), pub_key_bucket.to_owned());
    
    //opening public key
    let mut pub_key = Vec::new();
    let mut pub_key_file = File::open(postio_config_content.public_key.to_owned()).unwrap();
        pub_key_file.read_to_end(&mut pub_key);
    
    //sending public key
    create_file_on_aws(user_name.to_owned(), "public_key".to_string(), pub_key, pub_key_reg.to_owned(), pub_key_bucket.to_owned());

    //serializing config file
    let postio = toml::to_string(&postio_config_content).unwrap();

    //writing config file to ~/.postio
    let mut postio_config_file = File::create(postio_config_file_path).unwrap();
        postio_config_file.write_all(&postio.as_bytes());
}

fn create_postio_dir() {
    //create .postio directory in user's home 
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");

    create_dir(postio_dir.to_owned());
}

fn read_config() -> Config {
    //safely getting home directory and postio config path (or at least where it should be)
    let home_dir = home_dir().unwrap();
    let postio_dir = home_dir.to_owned().join(".postio");
    let config_file_path = postio_dir.to_owned().join("config");

    //opening and deserializing config
    let mut config_file_holder = File::open(&config_file_path).unwrap();
    let mut config_file = String::new();
        config_file_holder.read_to_string(&mut config_file).unwrap();

    let postio_config = toml::from_str(&config_file);

    //getting config file 
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
            return config;
        }
    }
}

fn aes_encrypter(file_path: String, pconfig: Config, to_user: String) -> FileBlob {
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
        unencrypted_file.read_to_end(&mut file_buffer);

    let encrypted_file = openssl::symm::encrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &file_buffer);
    
    //encrypying IV,Key with public key of receiver
    let (encrypted_iv, encrypted_key) = rsa_encrypter(pconfig, to_user, iv, key);

    //putting file, IV, and symmetic key, together into a blob and sending to AWS S3
    let fileBlobForAWS: FileBlob = FileBlob{file: encrypted_file.unwrap(), key: encrypted_key, iv: encrypted_iv};

    //return blob
    fileBlobForAWS
}

fn aes_decrypter(out_file_path: String, fileFromAWS: FileBlob, postio_config: Config) {
    //disecting fileblob from AWS
    let encrypted = fileFromAWS.file;
    let encrypted_key = fileFromAWS.key;
    let encrypted_iv = fileFromAWS.iv;

    //decrypting IV,Key with private certificates
    let (iv, key) = rsa_decrypter(postio_config.private_key, encrypted_iv, encrypted_key);

    //decrypting file with iv,key
    let unencrypted =  openssl::symm::decrypt(openssl::symm::Cipher::aes_256_cbc(), &key, Some(&iv), &encrypted);

    //writing file out
    let mut decrypted_file_path = File::create(out_file_path).unwrap();
        decrypted_file_path.write_all(&unencrypted.unwrap());
}

fn rsa_encrypter(pconfig: Config, to_user: String, unencrypted_iv: Vec<u8>, unencrypted_key: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //setting output buffer to write encrypted files to
    let mut enc_buffer_iv = [0u8;512];  //16 bytes
    let mut enc_buffer_key = [0u8;512]; //32 bytes

    //getting public key of receiver
    let public_key = aws_file_getter("public_key".to_string(), to_user, pconfig.public_key_store_region, pconfig.public_key_store);

    //opening your private key
    let mut pv_key = File::open(pconfig.private_key).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
        pv_key.read_to_end(&mut private_key);

    //enabling keys with openssl for RSA decryption
    let mut keys = openssl::rsa::Rsa::private_key_from_pem(&private_key).unwrap();
    keys =  openssl::rsa::Rsa::public_key_from_pem(&public_key).unwrap();

    //encrypting IV,Keys
    let iv_out = keys.public_encrypt(&unencrypted_iv, &mut enc_buffer_iv, openssl::rsa::PKCS1_OAEP_PADDING);
    let key_out = keys.public_encrypt(&unencrypted_key, &mut enc_buffer_key, openssl::rsa::PKCS1_OAEP_PADDING);

    (enc_buffer_iv.to_vec(), enc_buffer_key.to_vec())
}

fn rsa_decrypter(private_key_path: String, iv_to_decrypt: Vec<u8>, key_to_decrypt: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //opening your private key to decrypt IV,Key
    let mut private_key_file = File::open(private_key_path).unwrap();
    let mut private_key: Vec<u8> = Vec::new();
        private_key_file.read_to_end(&mut private_key);
    
    let keys = openssl::rsa::Rsa::private_key_from_pem(&private_key).unwrap();

    //buffer for decrypted iv,keys
    let mut decrypted_iv = [0u8;512]; //16
    let mut decrypted_key = [0u8;512]; //32

    //decrypting and truncated buffer to original lengths
    let file_out = keys.private_decrypt(&iv_to_decrypt, &mut decrypted_iv, openssl::rsa::PKCS1_OAEP_PADDING);
        let decrypted_iv_trunct: Vec<u8> = decrypted_iv[0..16].to_vec();

    let file_out = keys.private_decrypt(&key_to_decrypt, &mut decrypted_key, openssl::rsa::PKCS1_OAEP_PADDING);
        let decrypted_key_trunct: Vec<u8> = decrypted_key[0..32].to_vec();

    (decrypted_iv_trunct, decrypted_key_trunct)
}


fn open_file(file_path: String) -> Vec<u8> {
    //safe file opener
    let mut out_file: Vec<u8> = Vec::new();
    let mut file = File::open(file_path).expect("Problems with the file path you gave");

    file.read_to_end(&mut out_file).expect("Cannot read file");

    out_file
}

fn load_aws_credentials() -> Credentials {
    //loads aws creds from Bash enviromental variables
    let aws_access = var("AWS_ACCESS_KEY_ID").expect("Must specify AWS_ACCESS_KEY_ID");
    let aws_secret = var("AWS_SECRET_ACCESS_KEY").expect("Must specify AWS_SECRET_ACCESS_KEY");

    //returns credtials type for rust-s3
    Credentials::new(&aws_access, &aws_secret, None)
}

fn create_file_on_aws(user: String, file_name: String, file: Vec<u8>, region_input: String, bucket_name: String) {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
        user_sha_string+="/";
            user_sha_string+=&file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let bucket = Bucket::new(BUCKET, region, credentials);

    add_users_folder(user, region_input, bucket_name.to_owned());

    let (_, code) = bucket.put(&user_sha_string, &file, "text/plain").unwrap();

    if  code != 200 {
        println!("Sorry there was an error putting this file in the S3 HTTP code: {}", code);
    }
}

fn add_users_folder(user: String, region_input: String, bucket_name: String) {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    //using a blank string to add a folder
    let blank = String::new();

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

fn list_files_in_folder(user: String, region_input: String, bucket_name: String, listing: bool) -> Vec<String> {
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
    user_sha_string+="/";

    let mut output_list: Vec<String> = Vec::new();

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let mut bucket = Bucket::new(BUCKET, region, credentials);

    let (mut list, code) = bucket.list(&user_sha_string, Some("/")).expect("No files in folder");
    
    if code != 200 {
        println!("AWS error: HTTP code: {}", code);
    }
    
    //checking if there is a folder with the specified username
    if list.contents.len() == 0 {
        println!("Error: Your username wasn't found, this shouldn't happen logically");
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
                    match file_name.key.clone() {
                        Some(b) => {
                            let mut paths: Vec<&str> = b.split("/").collect(); //file name has folder name on top of it                            
                            output_list.push(paths[1].to_string());
                            if listing == true {
                                println!("{}) {}", file_count, paths[1]); //will only every be one folder deep by design
                            }
                        },
                        None => println!("Error No file exists here!") //should not get an error if there's a file that exists possibly a string error
                    }
                }
            }
        }
    }

    output_list
}

fn vec_to_hex_string(hex_vec: Vec<u8>) -> String {
    //formats a vector of u8s to padded hex string for storing username
    let mut out_string = String::new();

    for i in hex_vec {
        out_string += &format!("{:01$X}", i, 2);
    }

    out_string
}

fn aws_file_deleter(user: String, region_input: String, bucket_name: String, file_name: String) {
    //SHA512 username and emails (no crawling for emails here if we're using public S3s
    let user_sha = sha::sha512(user.to_lowercase().as_bytes());
    let user_sha_vec = user_sha.to_vec();
    let mut user_sha_string = vec_to_hex_string(user_sha_vec);
        user_sha_string+="/";
            user_sha_string+=&file_name;

    let credentials = load_aws_credentials();

    let region = region_input.parse().unwrap();
    let BUCKET = &bucket_name;

    let bucket = Bucket::new(BUCKET, region, credentials);

    let out = bucket.delete(&user_sha_string);

    match out {
        Ok(code) => {
            if code.1 != 200 {
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

fn help() {
    println!("postio:\n\n\t-i /path/to/file -u user@gmail.com\n\t-o [get|list]\n\t\tOptional: --all used to get all files in queue at once\n");
}

fn send_file(sending_file_path: String, to_user: String, pconfig: Config) {
    println!("Testing send files");

    //encrypting and sending a file to the AWS
    //Encrypting
    let out_blob: FileBlob = aes_encrypter(sending_file_path.to_owned(), pconfig.to_owned(), to_user.to_owned());

    //serializing to sent to AWS (need Vec<u8>) 
    let file_to_aws = toml::to_string(&out_blob).unwrap();

    let file_name_list: Vec<&str> = sending_file_path.split("/").collect();
    let file_name_st = file_name_list[file_name_list.len()-1].to_string();

    //sending to s3
    create_file_on_aws(to_user, file_name_st, file_to_aws.as_bytes().to_vec(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned());
}

fn get_file(action: String, all: bool, pconfig: Config) {
    println!("Testing get files");

    if action.to_lowercase() == "get".to_string() {
        if all == true {
            let file_list: Vec<String> =  list_files_in_folder(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), false);
            
            for i in file_list.iter() {
                //testing receiving file and decryption
                //first get file from AWS store
                let file_from_aws = aws_file_getter(i.to_owned(), pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned());

                //removing file from AWS 
                aws_file_deleter(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), i.to_owned()); //create an option to keep this
                
                //deserializing
                let out: FileBlob = toml::from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();
                
                //decrypting
                aes_decrypter(i.to_owned(), out, pconfig.to_owned());                 
            }
        }

        else {
            let file_list: Vec<String> =  list_files_in_folder(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), false);

            for (count, i) in file_list.iter().enumerate() {
                println!("{}) {}", count, i);
            }

            let mut file_to_get_index_str = String::new();
            print!("Please select a file (number) you wish to get: ");
            stdout().flush();
            stdin().read_line(&mut file_to_get_index_str);
             file_to_get_index_str.trim();
             file_to_get_index_str.pop();

            let file_to_get_index = file_to_get_index_str.parse::<usize>().expect("I expected the index of the file..");

            if file_to_get_index > file_list.len() {
                println!("You can't count");
                exit(1);
            }

            else {
                //testing receiving file and decryption
                //first get file from AWS store
                let file_from_aws = aws_file_getter(file_list[file_to_get_index].to_owned(), pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned());

                //removing file from AWS 
                aws_file_deleter(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), file_list[file_to_get_index].to_owned()); //create an option to keep this
                
                //deserializing
                let out: FileBlob = toml::from_str(&String::from_utf8(file_from_aws).unwrap()).unwrap();
                
                //decrypting
                aes_decrypter(file_list[file_to_get_index].to_owned(), out, pconfig.to_owned()); 
            }
        }

    }

    else if action.to_lowercase() == "list".to_string() {
        let file_list: Vec<String> = list_files_in_folder(pconfig.email.to_owned(), pconfig.file_store_region.to_owned(), pconfig.file_store.to_owned(), true);

        //jump into get if user would like
    }

    else {
        println!("Sorry only get or list are accepted for -o");
        exit(1);
    }
}

fn arg_parser(pconfig: Config) {

    let arg_list: Vec<String> = args().collect();

    match arg_list.len() {
        5 => {
            let file_index_test = arg_list.iter().position(|r| r == "-i");
            let user_index_test = arg_list.iter().position(|r| r == "-u");

            let (file_index, user_index) = match (file_index_test, user_index_test) {
                (Some(x), Some(y)) => (x+1, y+1),
                (Some(x), None) => {println!("<<Missing user to send file to>>"); help(); exit(1);},
                (None, Some(y)) => {println!("<<Missing file to send>>"); help(); exit(1);},
                (_, _) => {println!("<<Improperly formatted argument>>"); help(); exit(1);},
            };

            send_file(arg_list[file_index].to_owned(), arg_list[user_index].to_owned(), pconfig);
        },

        3 => {
    
            let action_index_test = arg_list.iter().position(|r| r == "-o");

            let action_index = match action_index_test {
                Some(x) => x+1,
                None => {println!("<<excepted -o [get|list]>>"); help(); exit(1);},
            };

            get_file(arg_list[action_index].to_owned(), false, pconfig);
        },

        4 => {
            let action_index_test = arg_list.iter().position(|r| r == "-o");
            let expect_subaction_index = arg_list.iter().position(|r| r == "--all");

            let action_index = match (action_index_test, expect_subaction_index) {
                (Some(x), Some(y)) => x+1,
                (Some(x), None) => {println!("<<Expected --all as the argument that follows -o [get|list]"); help(); exit(1);},
                (None, Some(y)) => {println!("<<Expect -o [get|list]>>"); help(); exit(1);},
                (None, None) => {println!("<<Improperly formatted argument>>"); help(); exit(1);},
            };

            get_file(arg_list[action_index].to_owned(), true, pconfig);
        },

        _ => help(),
    }

}


fn main() {
    //checking for configuration files
    let config_results = check_for_config();

    //if the config exists read it if not create directory and the file
    let postio_config: Config = match config_results {
        (true, true) => read_config(),
        (true, false) => {create_config(); read_config()},
        (_, _) => {create_postio_dir(); create_config(); read_config()},
    };

    arg_parser(postio_config);

}
