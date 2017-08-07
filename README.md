# Postio

## Overview
 Postio is a encrypted file sender and receiver. Written in [Rust](https://www.rust-lang.org/en-US/) Postio will encrypt a file (Using [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) mode) and send this file to an [AWS S3](https://aws.amazon.com/s3/). The initialization vector (IV) and symmetric key are also encrypted with [RSA-4096](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) private/public keys. Your public key is sent to the AWS S3 store (different S3 instance) for the sender to get your public key to properly encrypt the file. 

## How to Install
First you can clone the git repo and build yourself. 
- Current the code compiles on Mac OSX (10.12.5 Sierra), and CentOS 7.
- You'll need OpenSSL (for the crypto bindings) to compile.

Next, you'll want to add your AWS key ID and secret access key in your environment. You can do this in unix by adding this to your `.bashrc` or `.bash_profile` and running `source ~/.bashrc`or `source ~/.bash_profile` or by adding these to the terminal you currently have open:

```
export AWS_ACCESS_KEY_ID="your_key_id_here"
export AWS_SECRET_ACCESS_KEY="your_secret_access_here"
```

After that and you have a working binary you are good to go!

By the way, you can grab the pre-compiled binaries here: 
- [MacOS](https://s3-eu-west-1.amazonaws.com/postio-binary/x86_64-MacOS.tar)
- [CentOS](https://s3-eu-west-1.amazonaws.com/postio-binary/x86_64-Linux.tar)

More binaries are coming once I can set up a proper test suite for the different OSs. :)

## Command line options
 -i file -u user@email.com
 
    Uploads file for `-u` user
    
 -o get
 
    Enters get mode which will list files to download, user will then select the file they wish to receive
    
 -o list
 
    Just lists the files in your receive queue
    
 Optional: --all
 
    For use with `-o get` then proceeds to grab all files in queue
    
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

On the first run the program will set up the config file for you, including generating the RSA private/public keys. You can also generate these on your own:

```
openssl genrsa -des3 -out private.pem 4096
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```


## Contact
Feel free to put in a ticket for any issues in the code or to call me names.

Email: ricky<a>hosfelt.io
IRC: degausser (freenode and Mozilla)

Software will remain free but be a good sport and buy me a beer/coffee BTC: `1HJL1PMXi7rgALSo5cPLnRxhdPLBQDjQhd`

## TODO!
No particular order:

- Give user a `--no-delete` option to keep files on the AWS S3
- Give user a `--config-location` option to allow for multiple/different config file locations (default ~/.postio/config)
- Give users a break with less interaction
- Ability to just remove a file
- Bump code to be less messy after testing 
- Get user feedback :)

## Licensing and Warnings
I take no responsibly for getting your files stolen/deleted/hacked/cracked/etc. Also _please_ make sure you set up your AWS instance correctly or someone can run up the charges on your instance! Be smart, be secure!

Covered under the MIT license (C) Hosfelt.io
