# Overview

## Command line options
 -i file -r user@email.com
 -o get
 -o list
 Optional arg: -s sender's account (if you have multiple accounts set up)
 Optional arg: -a used to -o get all files at once

## Runthrough

### on any launch
    1) check for ~/.program_io.conf 
        1a) should have email, public key, and private key location
    2) if it does not exist go through steps to create it
        2a) get users desired email address 
        2b) generate keys (RAS2048) with approperate permissions 
        2c) send public key to s3 bucket for keys
    3) 

 when -i file -r user@email.com
    1) check senders conf file
        1a) if not present creat it
    2) check user's email is in the S3 bucket for keys
        2a) if not ask if you want to send unencrypted
            2ai) if yes, create folder (sha256 masked), send file (TLS), send email to receiver
            2aii) if no, invite user to create ~/.program_io.conf by sending email
        2b) if yes, grab receiver's public key, generate AES symmetic key, encrypt file, encrypt AES key with RSA pub/private, send file to receiver's folder with symmetic key

 when -o get
    1) list bucket contents
    2) list file and sender
        2a) give receiver option to get file, skip file, or delete file from bucket 
            2ai) do this until a user gets a file or reaches the end
            2aii) download file, senders public key, decrytp file
        2b) unless -a is supplied then get all files

 when -o list
    1) list bucket contents
    2) list files and sender's email

## TODO!

interface with S3
    file sender
    file getter
    bucket lister
        store files encyrpted with AES256 in storage (I heard you like AES so I AES'd your AES, dawg)

key creation
    RSA2048 for pub/private key (to encrypt symmetric key)
    AES256 (512?) for file encyrption

file encrypter
    gets public key of user from S3, generate AES symmetic key, encypt file with symmetic key, encrypt symmetic key with RSA public and this private, send file to S3
file decrypter 
    gets RSA public key of sender from S3, decrypts AES symmetic key, decrypts file boom

sha256 hashing on usernames for folders inside bucket
sah256 sender-user-filename for symmetic key file 
email interface to invite user, send notification of file ready to get
