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

mod common;
pub mod caesar;
pub mod vigenere;
pub mod rot13;
pub mod railfence;
pub mod fractionated_morse;
pub mod hill;
pub mod autokey;
pub mod affine;
pub mod polybius;
pub mod scytale;
pub mod columnar_transposition;
pub mod adfgvx;

pub use common::cipher::Cipher;
pub use caesar::Caesar;
pub use vigenere::Vigenere;
pub use railfence::Railfence;
pub use rot13 as ROT13;
pub use hill::Hill;
pub use fractionated_morse::FractionatedMorse;
pub use autokey::Autokey;
pub use affine::Affine;
pub use polybius::Polybius;
pub use scytale::Scytale;
pub use columnar_transposition::ColumnarTransposition;
pub use adfgvx::ADFGVX;
