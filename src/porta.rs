//! The Porta Cipher is a polyalphabetic substitution cipher. It was invented
//! by Giovanni Battista della Porta, an Italian polymath, in 1563.
//!
//! To generate the keystream for encryption, a key is repeated as often as
//! needed to match the number of (alphabetic) symbols in the plaintext message.
//! Finally, the (alphabetic) symbols of the message are substituted using a
//! substitution table. Since Porta is a reciprocal cipher, decryption works
//! the same as encryption.
//!
//! This implementation uses the following substitution table:
//! ```text
//! Keys| a b c d e f g h i j k l m n o p q r s t u v w x y z
//! ---------------------------------------------------------
//! A,B | n o p q r s t u v w x y z a b c d e f g h i j k l m
//! C,D | o p q r s t u v w x y z n m a b c d e f g h i j k l
//! E,F | p q r s t u v w x y z n o l m a b c d e f g h i j k
//! G,H | q r s t u v w x y z n o p k l m a b c d e f g h i j
//! I,J | r s t u v w x y z n o p q j k l m a b c d e f g h i
//! K,L | s t u v w x y z n o p q r i j k l m a b c d e f g h
//! M,N | t u v w x y z n o p q r s h i j k l m a b c d e f g
//! O,P | u v w x y z n o p q r s t g h i j k l m a b c d e f
//! Q,R | v w x y z n o p q r s t u f g h i j k l m a b c d e
//! S,T | w x y z n o p q r s t u v e f g h i j k l m a b c d
//! U,V | x y z n o p q r s t u v w d e f g h i j k l m a b c
//! W,X | y z n o p q r s t u v w x c d e f g h i j k l m a b
//! ```
//! For every key-message symbol pair `(k, m)`, the corresponding ciphertext
//! symbol is determined by selecting the table row according to `k` and the
//! column according to `m`.
//!
use common::alphabet::{self, Alphabet};
use common::cipher::Cipher;
use common::substitute;

#[cfg_attr(rustfmt, rustfmt_skip)]
const SUBSTITUTION_TABLE: [[usize; 26]; 13] = [
    [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12],
    [14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11],
    [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10],
    [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9],
    [17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8],
    [18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7],
    [19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6],
    [20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5],
    [21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4],
    [22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3],
    [23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2],
    [24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1],
    [25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0],
];

/// A Porta cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Porta {
    key: String,
}

impl Cipher for Porta {
    type Key = String;
    type Algorithm = Porta;

    /// Initialize a Porta cipher given a specific key.
    ///
    /// Will return `Err` if the key is empty or contains non-alphabetic symbols.
    fn new(key: String) -> Result<Porta, &'static str> {
        if key.is_empty() {
            return Err("Invalid key: must have at least one character.");
        }
        if !alphabet::STANDARD.is_valid(&key) {
            return Err("Invalid key: must contain only alphabetic characters.");
        }

        Ok(Porta { key })
    }

    /// Encrypt a message using a Porta cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Porta};
    ///
    /// let v = Porta::new("melon".into()).unwrap();
    /// assert_eq!(v.encrypt("We ride at dawn!").unwrap(), "Dt mpwx pb xtdl!");
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        substitute::key_substitution(message, &mut self.keystream(message), |mi, ki| {
            SUBSTITUTION_TABLE[ki / 2][mi]
        })
    }

    /// Decrypt a message using a Porta cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Porta};
    ///
    /// let v = Porta::new(String::from("melon")).unwrap();
    /// assert_eq!(v.decrypt("Dt mpwx pb xtdl!").unwrap(), "We ride at dawn!");
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        self.encrypt(ciphertext)
    }
}

impl Porta {
    /// Generate a keystream.
    ///
    /// For this, we simply repeat the key until we have enough symbols to
    /// encrypt all alphabetic symbols of the message.
    fn keystream(&self, message: &str) -> Vec<char> {
        let scrubbed_msg = alphabet::STANDARD.scrub(message);
        self.key.chars().cycle().take(scrubbed_msg.len()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let message = "attackatdawn";
        let porta = Porta::new("lemon".into()).unwrap();
        assert_eq!(porta.encrypt(message).unwrap(), "seauvppaxtel");
    }

    #[test]
    fn decrypt() {
        let ciphertext = "seauvppaxtel";
        let porta = Porta::new("lemon".into()).unwrap();
        assert_eq!(porta.decrypt(ciphertext).unwrap(), "attackatdawn");
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let porta = Porta::new("lemon".into()).unwrap();
        let ciphertext = porta.encrypt(message).unwrap();
        let decrypted = porta.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn with_utf8() {
        let message = "Peace 🗡️ Freedom and Liberty!";
        let porta = Porta::new("utfeightisfun".into()).unwrap();
        let ciphertext = porta.encrypt(message).unwrap();
        let decrypted = porta.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn valid_key() {
        assert!(Porta::new("LeMon".into()).is_ok());
    }

    #[test]
    fn key_with_symbols() {
        assert!(Porta::new("!em@n".into()).is_err());
    }

    #[test]
    fn key_with_whitespace() {
        assert!(Porta::new("wow this key is a real lemon".into()).is_err());
    }
}
