//! The Vigenère Cipher is a polyalphabetic substitution cipher. It was considered 'le chiffre
//! indéchiffrable' for 300 years until Friedrich Kasiski broke it in 1863.
//!
//! Note that this implementation does not mutate the calculated encoding/decoding key if the
//! message contains non-alphabetic symbols (including whitespace).
//!
//! For example, say the message was `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! encoding key would be `CRYPTCRYPTCRYP` not `CRYPTC RY PTCR`.
use std::iter;
use common::substitute;
use common::alphabet;
use common::cipher::Cipher;

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
        for c in key.chars() {
            //Keys can only contain characters in the known alphabet
            if alphabet::find_position(c).is_none(){
                return Err("Invalid key. Vigenere keys cannot contain non-alphabetic symbols.");
            }
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
    /// assert_eq!("O bzvrx uzt gvm ceklwo!", v.encrypt("I never get any credit!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption of a letter in a message:
        //         Ci = Ek(Mi) = (Mi + Ki) mod 26
        // Where;  Mi = position within the alphabet of ith char in message
        //         Ki = position within the alphabet of ith char in key
        let e_key = self.generate_keystream(message.len());

        substitute::key_substitution(message, &e_key,
            |mi, ki| alphabet::modulo((mi + ki) as isize))
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
    /// assert_eq!("I never get any credit!", v.decrypt("O bzvrx uzt gvm ceklwo!").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        let d_key = self.generate_keystream(ciphertext.len());

        substitute::key_substitution(ciphertext, &d_key,
            |ci, ki| alphabet::modulo(ci as isize - ki as isize))
    }
}

impl Vigenere {
    /// Generates a keystream for a given `msg_length`.
    ///
    /// Will simply return a copy of the key if its length is already larger than the message.
    fn generate_keystream(&self, msg_length: usize) -> String {
        //The key is large enough for the message already
        if self.key.len() >= msg_length {
            return self.key.clone();
        }

        //Repeat the key until it fits within the length of the message
        let keystream = iter::repeat(self.key.clone()).take((msg_length / self.key.len()) + 1)
            .collect::<String>();

        keystream[0..msg_length].to_string()
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
    fn with_emoji(){
        let v = Vigenere::new(String::from("emojisarefun")).unwrap();
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = v.encrypt(message).unwrap();
        let decrypted = v.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn fit_smaller_key() {
        let message = "We are under seige!"; //19 character message
        let v = Vigenere::new(String::from("lemon")).unwrap(); //key length of 5

        assert_eq!("lemonlemonlemonlemo", v.generate_keystream(message.len()));
        assert!(v.generate_keystream(message.len()).len() >= message.len());
    }

    #[test]
    fn fit_larger_key() {
        let message = "hi";
        let v = Vigenere::new(String::from("lemon")).unwrap();

        assert_eq!("lemon", v.generate_keystream(message.len()));
        assert!(v.generate_keystream(message.len()).len() >= message.len());
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
