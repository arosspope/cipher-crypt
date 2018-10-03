//! A cryptographic tomb of ciphers forgotten by time.
//!
//! ## Example usage
//!
//! ```rust
//! extern crate cipher_crypt;
//!
//! use cipher_crypt::{Cipher, Caesar, ROT13};
//!
//! fn main(){
//!   let m1 = "I am my own inverse";
//!   assert_eq!(m1, ROT13::apply(&ROT13::apply(m1)));
//!
//!   let m2 = "Attack at dawn 🗡️";
//!   let c = Caesar::new(3).unwrap();
//!   assert_eq!(m2, c.decrypt(&c.encrypt(m2).unwrap()).unwrap());
//! }
//! ```
//!
//! ## Disclaimer
//!
//! There's a reason these archaic methods are no longer used - it's because they are extremely
//! easy to crack! Intended for learning purposes only, these ciphers should not be used to
//! encrypt data of any real value.
extern crate num;
extern crate rulinalg;

#[macro_use]
extern crate lazy_static;
extern crate lipsum;
#[macro_use]
extern crate maplit;

pub mod adfgvx;
pub mod affine;
pub mod autokey;
pub mod baconian;
pub mod caesar;
pub mod columnar_transposition;
mod common;
pub mod fractionated_morse;
pub mod hill;
pub mod playfair;
pub mod polybius;
pub mod porta;
pub mod railfence;
pub mod rot13;
pub mod scytale;
pub mod vigenere;

pub use adfgvx::ADFGVX;
pub use affine::Affine;
pub use autokey::Autokey;
pub use baconian::Baconian;
pub use caesar::Caesar;
pub use columnar_transposition::ColumnarTransposition;
pub use common::cipher::Cipher;
pub use fractionated_morse::FractionatedMorse;
pub use hill::Hill;
pub use playfair::Playfair;
pub use polybius::Polybius;
pub use porta::Porta;
pub use railfence::Railfence;
pub use rot13 as ROT13;
pub use scytale::Scytale;
pub use vigenere::Vigenere;
