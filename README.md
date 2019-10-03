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
cipher-crypt = "^0.16"
```

Using the crate as such:

```rust
extern crate cipher_crypt;

use cipher_crypt::{Cipher, Caesar};

fn main(){
  let m2 = "Attack at dawn 🗡️";
  let c = Caesar::new(3);
  assert_eq!(m2, c.decrypt(&c.encrypt(m2).unwrap()).unwrap());
}
```

## Ciphers

The crypt only contains a few ciphers, but with time (and your help) it will have even more! A list of what is planned for the future and what is currently implemented is as follows.

- [x] ADFGVX
- [x] Affine
- [x] Autokey
- [x] Baconian
- [x] Caesar
- [x] Columnar Transposition
- [x] Fractionated Morse
- [x] Hill
- [x] Homophonic
- [x] Playfair
- [x] Polybius Square
- [x] Porta
- [x] Rail-fence
- [x] ROT13
- [x] Scytale
- [x] Vigenère
- [ ] Bifid
- [ ] Four-Square
- [ ] Straddle Checkerboard
- [ ] Trifid

## Contributions

Contributions are extremely welcome. A good place to start would be helping to implement new algorithms. General cleanup and improvements of the code would also be greatly appreciated.

## Disclaimer

There's a reason these archaic methods are no longer used - its because they are extremely easy to crack!
Intended for learning purposes only, these ciphers should not be used to encrypt data of any real value.
