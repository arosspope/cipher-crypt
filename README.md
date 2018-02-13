# Cipher-crypt

[![Crates.io](https://img.shields.io/crates/v/cipher-crypt.svg)](https://crates.io/crates/cipher-crypt)
[![Documentation](https://docs.rs/cipher-crypt/badge.svg)](https://docs.rs/cipher-crypt)
[![Build Status](https://travis-ci.org/arosspope/cipher-crypt.svg?branch=master)](https://travis-ci.org/arosspope/cipher-crypt)

A library of historic cryptographic algorithms implemented in rust.

## Usage

Importing this crypt of ciphers is as easy as
adding the following to your Cargo.toml:

```toml
[dependencies]
cipher-crypt = "^0.10"
```

Using the crate as such:

![rot13-demo](http://i.imgur.com/5pywJBn.gif)

## Ciphers

The crypt only contains a few ciphers, but with time (and your help) it will have even more! A list of what is planned for the future and what is currently implemented is as follows.

- [x] ROT13
- [x] Caesar
- [x] Affine
- [x] Rail-fence
- [x] Polybius Square
- [x] Scytale
- [x] Autokey
- [x] Vigenère
- [x] Hill
- [x] Fractionated Morse
- [x] Columnar Transposition
- [ ] Baconian
- [ ] Porta
- [ ] Homophonic
- [ ] Four-Square
- [ ] Playfair
- [ ] ADFGVX
- [ ] Bifid
- [ ] Straddle Checkerboard
- [ ] Trifid

## Contributions

Contributions are extremely welcome. A good place to start would be helping to implement new algorithms. General cleanup and improvements of the code would also be greatly appreciated.

## Disclaimer

There's a reason these archaic methods are no longer used - its because they are extremely easy to crack!
Intended for learning purposes only, these ciphers should not be used to encrypt data of any real value.
