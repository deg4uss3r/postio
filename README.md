# Postio

## Overview
 Postio is a encrypted file sender and receiver. Written in [Rust](https://www.rust-lang.org/en-US/) Postio will encrypt a file (Using [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) mode) and send this file to an [AWS S3](https://aws.amazon.com/s3/). The initialization vector (IV) and symmetric key are also encrypted with [RSA-4096](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) private/public keys. Your public key is sent to the AWS S3 store (different S3 instance) for the sender to get your public key to properly encrypt the file. 

## How to Install
First you can clone the git repo and build yourself. 
- Current the code compiles on Mac OSX (10.12.5 Sierra), and CentOS 7.
  - If you compile yourself make sure you have `openssl`, `openssl-devel`, and `gcc` already installed on your machine
- You'll need OpenSSL (for the crypto bindings) to compile.

Next, you'll want to add your AWS key ID and secret access key in your environment. You can do this in unix by adding this to your `.bashrc` or `.bash_profile` and running `source ~/.bashrc`or `source ~/.bash_profile` or by adding these to the terminal you currently have open:

```
export AWS_ACCESS_KEY_ID="your_key_id_here"
export AWS_SECRET_ACCESS_KEY="your_secret_access_here"
```

After that and you have a working binary you are good to go!

By the way, you can grab the pre-compiled binaries (in the near future) by doing `cargo install postio`: 

## Options
```
Postio 0.3.0
Ricky (Degausser) <Ricky@Hosfelt.io>
Send and receive encrypted files

USAGE:
    Postio [FLAGS] [OPTIONS]

FLAGS:
    -x, --setup        Create config file and populate settings
    -l, --list         List files in your queue
    -d, --no-delete    Do not delete files after getting them
    -a, --all          Get all files at once
    -Q, --clear        Deletes all files in your queue

OPTIONS:
    -g <number in queue>                  Gets file from queue [default: ]
    -s </file/to/send>                    Send file to user
    -c, --config </path/to/config>        Sets a custom config file (defaults to $HOME/.postio/config)
    -o </path/to/output/directory>        Change output directory to something other than the current directory
    -u <User@email.com>                   User to receive file
```

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

On the first run the program will set up the config file for you (or you can ran `postio -x` to setup another config file, including generating the RSA private/public keys. You can also generate these on your own:

```
openssl genrsa -des3 -out private.pem 4096
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```


## Contact
Feel free to put in a ticket for any issues in the code or to call me names.

Email: ricky<a>hosfelt.io
IRC: degausser (freenode and Mozilla)

Software will remain free but be a good sport and buy me a beer/coffee BTC: `1HJL1PMXi7rgALSo5cPLnRxhdPLBQDjQhd`
 
## Licensing and Warnings
I take no responsibly for getting your files stolen/deleted/hacked/cracked/etc. Also _please_ make sure you set up your AWS instance correctly or someone can run up the charges on your instance! Be smart, be secure!

Covered under the MIT license (C) Hosfelt.io
