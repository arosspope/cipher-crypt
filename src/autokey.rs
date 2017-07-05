//! The Autokey Cipher is a polyalphabetic substitution cipher. It was considered 'le chiffre
//! indéchiffrable' for 300 years until Friedrich Kasiski broke it in 1863.
//!
//! Note that this implementation does not mutate the calculated encoding/decoding key if the
//! message contains non-alphabetic symbols (including whitespace).
//!
//! For example, say the message was `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! encoding key would be `CRYPTCRYPTCRYP` not `CRYPTC RY PTCR`.
use common::cipher::Cipher;
use common::{substitute, alphabet};

/// An Autokey cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Autokey {
    key: String,
}

impl Cipher for Autokey {
    type Key = String;
    type Algorithm = Autokey;

    /// Initialise an Autokey cipher given a specific key.
    ///
    /// Will return `Err` if the key contains non-alphabetic symbols.
    fn new(key: String) -> Result<Autokey, &'static str> {
        if !alphabet::is_alphabetic_only(&key) {
            return Err("Invalid key. Autokey keys cannot contain non-alphabetic symbols.");
        }

        Ok(Autokey { key: key })
    }

    /// Encrypt a message using an Autokey cipher.
    ///
    /// As the message is potentially used as part of the key to encrypt, it can only contain
    /// alphabetic characters. Messages with whitespace and symbols will be rejected.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Autokey};
    ///
    /// let a = Autokey::new(String::from("giovan")).unwrap();
    /// assert_eq!("O bzvrx uzt gvm ceklwo!", v.encrypt("I never get any credit!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption of a letter in a message:
        //         Ci = Ek(Mi) = (Mi + Ki) mod 26
        // Where;  Mi = position within the alphabet of ith char in message
        //         Ki = position within the alphabet of ith char in key
        let e_key = self.fit_key(message);

        substitute::key_substitution(message, &e_key,
            |mi, ki| alphabet::modulo((mi + ki) as isize))
    }

    /// Decrypt a message using an Autokey cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Autokey};
    ///
    /// let a = Autokey::new(String::from("giovan")).unwrap();
    /// assert_eq!("I never get any credit!", v.decrypt("O bzvrx uzt gvm ceklwo!").unwrap());
    /// ```
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        let d_key = self.fit_key(cipher_text);

        substitute::key_substitution(cipher_text, &d_key,
            |mi, ki| alphabet::modulo(mi as isize - ki as isize))
    }
}

impl Autokey {
    /// Fits the key to the length of the message by concatonating the key and the message itself.
    ///
    /// Will simply return a copy of the key if its length is already larger than the message.
    fn fit_key(&self, message: &str) -> String {
        let mut key_copy = self.key.clone();
        let trimmed_msg = Autokey::strip_symbols(message);

        if key_copy.len() >= trimmed_msg.len() {
            return Autokey::expand_on_symbol(&key_copy, message)[0..trimmed_msg.len()].to_string();
        }

        key_copy.push_str(&trimmed_msg);

        key_copy = Autokey::expand_on_symbol(&key_copy, message);

        key_copy[0..message.len()].to_string()
    }

    /// Will strip any non-alphabetic symbols from the text.
    ///
    fn strip_symbols(text: &str) -> String {
        text.chars().into_iter()
            .filter(|&c| alphabet::find_position(c).is_some()).collect()
    }

    /// Will expand key at the position of a non-alphabetic symbol in the text
    fn expand_on_symbol(key: &str, text: &str) -> String {
        let mut expanded_key = String::from(key);
        for (i, c) in text.chars().enumerate() {
            if alphabet::find_position(c).is_none() {
                expanded_key.insert(i, ' ');
            }
        }

        expanded_key = expanded_key.trim().to_string();

        expanded_key
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "defend the east wall of the castle";
        let v = Autokey::new(String::from("fortification")).unwrap();
        assert_eq!("iswxvi bje xigg zeqp bi moi gakmhe", v.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_test() {
        let cipher_text = "lxfopktmdcgn";
        let v = Autokey::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(cipher_text).unwrap());
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let v = Autokey::new(String::from("giovan")).unwrap();

        let cipher_text = v.encrypt(message).unwrap();
        let plain_text = v.decrypt(&cipher_text).unwrap();

        assert_eq!(plain_text, message);
    }

    #[test]
    fn with_emoji(){
        let v = Autokey::new(String::from("emojisarefun")).unwrap();
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = v.encrypt(message).unwrap();
        let decrypted = v.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    //Testing the ability to fit a key
    #[test]
    fn fit_smaller_key() {
        let message = "We are under seige!"; //19 character message
        let v = Autokey::new(String::from("lemon")).unwrap(); //key length of 5

        assert_eq!("le mon Weare under", v.fit_key(message));
    }

    #[test]
    fn fit_larger_key() {
        let message = "hi !@$%";
        let v = Autokey::new(String::from("lemon")).unwrap();

        assert_eq!("lemon", v.fit_key(message));
    }

    //Testing ability to strip symbols
    #[test]
    fn strip(){
        assert_eq!(Autokey::strip_symbols(" he@1y! 2"), "hey");
    }

    //Testing validity of key
    #[test]
    fn valid_key() {
        assert!(Autokey::new(String::from("LeMon")).is_ok());
    }

    #[test]
    fn key_with_symbols() {
        assert!(Autokey::new(String::from("!em@n")).is_err());
    }

    #[test]
    fn key_with_whitespace() {
        assert!(Autokey::new(String::from("wow this key is a real lemon")).is_err());
    }
}
