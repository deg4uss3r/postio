# Postio

## Overview
 Postio is a encrypted file sender and receiver. Written in [Rust](https://www.rust-lang.org/en-US/) Postio will encrypt a file (Using [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) or [ChaCha](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) mode, using [Curve 25519](https://en.wikipedia.org/wiki/Curve25519) public/private keys from [Dalek](https://doc.dalek.rs/curve25519_dalek/)) and send this file to an [AWS S3](https://aws.amazon.com/s3/). Your public key is sent to the AWS S3 store (different S3 instance) for the sender to get your public key to properly encrypt the file. 

## How to Install

You'll definitely need [rust](https://rustup.rs) if you want to compile from source, also `git`. 

### MacOS

 - Required packages
  - `homebrew`
  - `openssl@1.1` (via `homebrew`)

### CentOS (Fedora)

 - Required packages
  - `gcc`
  - `zlib-devel`
  - `openssl-devel` (version 1.0.2+ or if you want to use ChaCha version 1.1.0+)

### Ubuntu (Debian)

 - Required packages
  - `gcc`
  - `make`
  - `openssl` (version 1.0.2+ or if you want to use ChaCha version 1.1.0+)
  - `libssl-dev`
  - `zlib1g-dev` (for zlib compression)

Finally install `postio` by `cargo install postio`

Next, you'll want to add your AWS key ID and secret access key in your environment. You can do this in unix by adding this to your `.bashrc` or `.bash_profile` and running `source ~/.bashrc`or `source ~/.bash_profile` or by adding these to the terminal you currently have open (limit control of these files, and make sure you do not accidentally check them in to a git repository!):

```
export AWS_ACCESS_KEY_ID="your_key_id_here"
export AWS_SECRET_ACCESS_KEY="your_secret_access_here"
```

After that and you have a working binary you are good to go!

## Options

```
Postio 0.6.0
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
    -g <number in queue>                  Gets file from queue
    -s </file/to/send>                    Send file to user
    -c, --config </path/to/config>        Sets a custom config file (defaults to $HOME/.postio/config)
        --encrypt <AES or ChaCha>         Set the encryption algorithm [default: AES]
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

On the first run the program will set up the config file for you (or you can ran `postio -x` to setup another config file, including generating the 25519 private/public keys. 

## Contact
Feel free to put in a ticket for any issues in the code or to call me names.

Email: ricky`@`hosfelt.io

IRC: degausser (freenode and Mozilla)

Software will remain free but be a good sport and buy me a beer/coffee BTC: `1HJL1PMXi7rgALSo5cPLnRxhdPLBQDjQhd`
 
## Licensing and Warnings
I take no responsibly for getting your files stolen/deleted/hacked/cracked/etc. Also _please_ make sure you set up your AWS instance correctly or someone can run up the charges on your instance! Be smart, be secure!

Covered under the MIT license (C) Hosfelt.io
