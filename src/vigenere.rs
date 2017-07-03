//! The Vigenère Cipher is a polyalphabetic substitution cipher. It was considered 'le chiffre
//! indéchiffrable' for 300 years until Friedrich Kasiski broke it in 1863.
//!
//! Note that this implementation does not mutate the calculated encoding/decoding key if the
//! message contains non-alphabetic symbols (including whitespace).
//!
//! For example, say the message was `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! encoding key would be `CRYPTCRYPTCRYP` not `CRYPTC RY PTCR`.
use std::iter;
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
        let e_key = self.fit_key(message.len());

        Vigenere::poly_substitute(message, e_key, |mi, ki| (mi + ki) % 26)
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
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        let d_key = self.fit_key(cipher_text.len());

        let decrypt = |ci, ki| {
            let a: isize = ci as isize - ki as isize;
            (((a % 26) + 26) % 26) as usize
            //Rust does not natievly support negative wrap around modulo operations
        };

        Vigenere::poly_substitute(cipher_text, d_key, decrypt)
    }
}

impl Vigenere {
    /// Fits the key to a given `msg_length`.
    ///
    /// Will simply return a copy of the key if its length is already larger than the message.
    fn fit_key(&self, msg_length: usize) -> String {
        let key_copy = self.key.clone();

        if key_copy.len() >= msg_length {
            return key_copy; //The key is large enough for the message already
        }

        //Repeat the key until it fits within the length of the message
        let mut repeated_key = iter::repeat(key_copy).take((msg_length / self.key.len()) + 1)
            .collect::<String>();

        repeated_key.truncate(msg_length);
        repeated_key
    }

    /// Performs a poly substitution on a piece of text based on the index of its characters
    /// within the alphabet.
    ///
    /// This substitution is defined by the closure `calc_index`
    fn poly_substitute<F>(text: &str, key: String, calc_index: F) -> Result<String, &'static str>
        where F: Fn(usize, usize) -> usize
    {
        let mut s_text = String::new();

        for (i, tc) in text.chars().enumerate() {
            //Find the index of the character in the alphabet (if it exists in there)
            let tpos = alphabet::find_position(tc);
            match tpos {
                Some(ti) => {
                    //Get the key character at position i
                    if let Some(kc) = key.chars().nth(i) {
                        //Get position of character within the alphabet
                        if let Some(ki) = alphabet::find_position(kc) {
                            //Calculate the index and retrieve the letter to substitute
                            let si = calc_index(ti, ki);
                            if let Some(s) = alphabet::get_letter(si, tc.is_uppercase()){
                                s_text.push(s);
                            } else {
                                return Err("Calculated a substitution index outside of the known alphabet.")
                            }
                        } else {
                            return Err("Vigenere key contains a non-alphabetic symbol.")
                        }
                    } else {
                        return Err("Fitted key is too small for message length.")
                    }

                },
                None => s_text.push(tc), //Push non-alphabetic chars 'as-is'
            }
        }

        Ok(s_text)
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
        let cipher_text = "lxfopvefrnhr";
        let v = Vigenere::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(cipher_text).unwrap());
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let v = Vigenere::new(String::from("giovan")).unwrap();

        let cipher_text = v.encrypt(message).unwrap();
        let plain_text = v.decrypt(&cipher_text).unwrap();

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

        assert_eq!("lemonlemonlemonlemo", v.fit_key(message.len()));
        assert!(v.fit_key(message.len()).len() >= message.len());
    }

    #[test]
    fn fit_larger_key() {
        let message = "hi";
        let v = Vigenere::new(String::from("lemon")).unwrap();

        assert_eq!("lemon", v.fit_key(message.len()));
        assert!(v.fit_key(message.len()).len() >= message.len());
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
