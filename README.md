# CRYPT, an encryption/decryption tool
![head](./assets/head.png)

<div align=center>
  <a href="https://github.com/ninja-left/CRYPT/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/ninja-left/CRYPT">
  </a>
  <a href="https://github.com/ninja-left/CRYPT">
    <img src="https://img.shields.io/github/commit-activity/m/ninja-left/CRYPT">
  </a>

![Latest version](https://img.shields.io/github/v/tag/ninja-left/CRYPT?label=Version&color=black) ![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)

</div>


## What?
CRYPT is a tool that allows you to encrypt or decrypt texts.

## Why?
The main reason I wrote this program was having access to common encodings and hash
functions in one place. Later I added more functions and ciphers. All releases have
a script named `CryptB.py` which takes 2 files as input and output and encodes or
decodes the input file line by line while writing to output file.

## What encodings, ciphers, and hashes are supported?
1. Encodings:
   - Base16
   - Base32
   - Base64
   - Base85

2. Ciphers:
   - Caesar Cipher
   - Morse Code
   - Baconian Cipher
   - Vigenère Cipher

3. Hashes:
   - MD5
   - Md5 Crypt
   - SHA256 & SHA512
   - SHA256 & SHA512 Crypt
   - NT
   - BCrypt
   - Argon2
   - PBKDF2+SHA256 & PBKDF2+SHA512
   - Hash Cracking with a wordlist or by Bruteforcing

## Installation
1. Install Python3
2. Clone this git repository OR Download source code from Releases page
3. Unpack the zip or tar
4. (Recommended) Create a virtual environment and use that:
    ```shell
    python3 -m venv venv
    ```
    On Mac/Linux:
    ```shell
    source ./venv/bin/activate
    ```
    On Windows
    ```shell
    .\venv\Scripts\activate
    ```
5. install the libraries in `requirements.txt` using:
    ```shell
    pip install -r requirements.txt
    ```

Note: This app uses `pyperclip` in order to copy/paste.
1. On Windows, no additional modules are needed.
2. On Mac, this module makes use of the pbcopy and pbpaste commands, which should come with the os.
3. On Linux, this module makes use of the xclip or xsel commands, which should come with the os. Otherwise run “sudo apt-get install xclip” or “sudo apt-get install xsel” (Note: xsel does not always seem to work.)

## Usage
```shell
python3 Crypt-?.?.?.py
```
or
```shell
./Crypt-?.?.?.py
```
Where `?.?.?` is the version.

## Support
If you encounter any issues or bugs, feel free to open an issue about it on this repo and I'll try to help.

## License
This project is licensed under GPL v3.0. See [LICENSE] for details.

## Contributing
Thanks in advance for considering to help me on this project.
You can read [CONTRIBUTING.md] for details on contributing to the project.

## Roadmap
- [ ] Add the functions


[LICENSE]: ./LICENSE
[CONTRIBUTING.md]: ./CONTRIBUTING.md