# Postio

## Overview
 Postio is a encrypted file sender and receiver. Written in [Rust](https://www.rust-lang.org/en-US/) Postio will encrypt a file (Using [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) mode and send this file to an [AWS S3](https://aws.amazon.com/s3/). The initialization vectory and symmetic key are also encryoted with [RSA-4096](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) private/public keys. Your public key is sent to the AWS S3 store (differnt S3 instance) for the sender to get your public key to proply encrypt the file. 


## Command line options
 -i file -u user@email.com
    Uploads file for `-u` user
 -o get
    Enters get mode which will list files to download, user will then select the file they wish to recvieve
 -o list
    Just lists the files in your receive queue
 Optional: --all
    For use with `-o get` then proceeds to grab all files in queue
 Optional: --config-location
    Specify custom postio configuration location normally in `~/.postio/config`

## Config File Structure
Using [serde](https://crates.io/crates/serde) postio will parse the config file in toml format. 

The configure file should look like below: 

```
email = "ricky@hosfelt.io"
private_key = "/Users/rthosfelt/.postio/private_key.pem"
public_key = "/Users/rthosfelt/.postio/public_key.pem"
file_store = "postio"
file_store_region = "eu-west-2"
public_key_store = "postio-keys"
public_key_store_region = "eu-central-1"
```

## TODO!
No particular order

- Arg parser
- Allow user to specify custom location for config file
- Write file lister
- Write file selector

