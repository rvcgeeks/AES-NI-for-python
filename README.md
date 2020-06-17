# AES-NI for python

This is a simple module which acts as a glue for the aes hardware acceleration 
for python 2 or 3

## Features

1) hardware acceleration hence robust and fastest aes possible in python 2 or 3
2) implicitly takes care of padding
3) code taken from my copyrighted product RVCvault - A Multi level file encryption system

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

1) 64bit Hardware (CPU like intel or amd) that supports AES-NI
2) c compiler with -march=native support
3) python
4) python development libraries for its specific version

## Deployment

First you need to compile the c code to .dll (in windows) and .so (in linux) by command
```
cc aes.c -march=native -fPIC $(python-config --includes) -shared -o aes.so 
```
Then execute the test program
```
python test.py
```
## Manual

   This module has three functions 
   
   1) encrypt(key : bytearray, plaintext : bytearray) -> bytearray :
   
   which returns a ciphertext of 16 byte multiple.
   if the plaintext is not multiple of 16 bytes then,
   it will be resized to 16 byte multiple padded with zeros.
   key must have 16 bytes in it
   
   2) decrypt(key : bytearray, ciphertext : bytearray) -> bytearray :
   
   which returns decrypted plaintext. given the same key
   and ciphertext but with multiple of 16 bytes. If not this
   function will throw ValueError.
   
   3) check() -> bool :
   
   which returns True if CPU supports AES-NI else False.

## Author

* **Rajas Chavadekar** 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
