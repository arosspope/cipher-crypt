//! The Vigenère Cipher is a polyalphabetic substitution cipher. It was considered 'le chiffre
//! indéchiffrable' for 300 years until Friedrich Kasiski broke it in 1863.
//!
//! For example, given the message `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! encoding key would be `CRYPTC RY PTCR`.
use std::iter;
use common::substitute;
use common::alphabet;
use common::cipher::Cipher;
use common::alphabet::Alphabet;

/// A Vigenère cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Vigenere {
    key: String,
}

impl Cipher for Vigenere {
    type Key = String;
    type Algorithm = Vigenere;

    /// Initialise a Vigenère cipher given a specific key.
    ///
    /// Will return `Err` if the key contains non-alphabetic symbols.
    fn new(key: String) -> Result<Vigenere, &'static str> {
        if key.len() < 1 {
            return Err("Invalid key. It must have at least one character.");
        } else if !alphabet::STANDARD.is_valid(&key) {
            return Err("Invalid key. Vigenère keys cannot contain non-alphabetic symbols.");
        }

        Ok(Vigenere { key: key })
    }

    /// Encrypt a message using a Vigenère cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Vigenere};
    ///
    /// let v = Vigenere::new(String::from("giovan")).unwrap();
    /// assert_eq!("O vsqee mmh vnl izsyig!", v.encrypt("I never get any credit!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption of a letter in a message:
        //         Ci = Ek(Mi) = (Mi + Ki) mod 26
        // Where;  Mi = position within the alphabet of ith char in message
        //         Ki = position within the alphabet of ith char in key
        substitute::key_substitution(message, &mut self.keystream(message), |mi, ki| {
            alphabet::STANDARD.modulo((mi + ki) as isize)
        })
    }

    /// Decrypt a message using a Vigenère cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Vigenere};
    ///
    /// let v = Vigenere::new(String::from("giovan")).unwrap();
    /// assert_eq!("I never get any credit!", v.decrypt("O vsqee mmh vnl izsyig!").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        substitute::key_substitution(ciphertext, &mut self.keystream(ciphertext), |ci, ki| {
            alphabet::STANDARD.modulo(ci as isize - ki as isize)
        })
    }
}

impl Vigenere {
    /// Generates a keystream based on the base key and message length.
    ///
    /// Will simply return a copy of the base key if its length is already larger than the
    /// message.
    fn keystream(&self, message: &str) -> Vec<char> {
        //The key will only be used to encrypt the portion of the message that is alphabetic
        let scrubbed_msg = alphabet::STANDARD.scrub(message);

        //The key is large enough for the message already
        if self.key.len() >= scrubbed_msg.len() {
            return self.key[0..scrubbed_msg.len()].chars().collect();
        }

        //Repeat the base key until it fits within the length of the scrubbed message
        let keystream = iter::repeat(self.key.clone())
            .take((scrubbed_msg.len() / self.key.len()) + 1)
            .collect::<String>();

        keystream[0..scrubbed_msg.len()].chars().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "attackatdawn";
        let v = Vigenere::new(String::from("lemon")).unwrap();
        assert_eq!("lxfopvefrnhr", v.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_test() {
        let ciphertext = "lxfopvefrnhr";
        let v = Vigenere::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let v = Vigenere::new(String::from("giovan")).unwrap();

        let ciphertext = v.encrypt(message).unwrap();
        let plain_text = v.decrypt(&ciphertext).unwrap();

        assert_eq!(plain_text, message);
    }

    #[test]
    fn with_utf8() {
        let v = Vigenere::new(String::from("utfeightisfun")).unwrap();
        let message = "Peace 🗡️ Freedom and Liberty!";
        let encrypted = v.encrypt(message).unwrap();
        let decrypted = v.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn smaller_base_key() {
        let message = "We are under seige!"; //19 character message
        let v = Vigenere::new(String::from("lemon")).unwrap(); //key length of 5

        assert_eq!(
            vec![
                'l', 'e', 'm', 'o', 'n', 'l', 'e', 'm', 'o', 'n', 'l', 'e', 'm', 'o', 'n'
            ],
            v.keystream(message)
        );
    }

    #[test]
    fn larger_base_key() {
        let message = "hi";
        let v = Vigenere::new(String::from("lemon")).unwrap();

        assert_eq!(vec!['l', 'e'], v.keystream(message));
    }

    #[test]
    fn valid_key() {
        assert!(Vigenere::new(String::from("LeMon")).is_ok());
    }

    #[test]
    fn key_with_symbols() {
        assert!(Vigenere::new(String::from("!em@n")).is_err());
    }

    #[test]
    fn key_with_whitespace() {
        assert!(Vigenere::new(String::from("wow this key is a real lemon")).is_err());
    }
}
