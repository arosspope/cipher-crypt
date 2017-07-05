//! The Autokey Cipher is a polyalphabetic substitution cipher. It was considered 'le chiffre
//! indéchiffrable' for 300 years until Friedrich Kasiski broke it in 1863.
//!
//! Note that this implementation does not mutate the calculated encoding/decoding key if the
//! message contains non-alphabetic symbols (including whitespace).
//!
//! For example, say the message was `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! encoding key would be `CRYPTCRYPTCRYP` not `CRYPTC RY PTCR`.
use std::iter;
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
        if key.len() > 0 && !alphabet::is_alphabetic_only(&key) {
            return Err("Invalid key. Autokey keys cannot contain non-alphabetic symbols.");
        }

        Ok(Autokey { key: key })
    }

    /// Encrypt a message using an Autokey cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Autokey};
    ///
    /// let a = Autokey::new(String::from("giovan")).unwrap();
    /// assert_eq!("O bzvrz kzx grr ppgumw!", a.encrypt("I never get any credit!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption of a letter in a message:
        //         Ci = Ek(Mi) = (Mi + Ki) mod 26
        // Where;  Mi = position within the alphabet of ith char in message
        //         Ki = position within the alphabet of ith char in key
        substitute::key_substitution(message, &self.encrypt_keystream(message),
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
    /// assert_eq!("I never get any credit!", a.decrypt("O bzvrz kzx grr ppgumw!").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        //
        // Please note that the decrypt keystream is generated 'on the fly' as the ciphertext
        // is decrypted.
        self.autokey_decrypt(ciphertext)
    }
}

impl Autokey {
    fn autokey_decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let mut plaintext = String::new();

        //We start the stream with the base key
        let mut keystream = String::from(self.key.clone());

        for (i, cc) in ciphertext.chars().enumerate() {
            //Find the index of the ciphertext character in the alphabet (if it exists in there)
            let tpos = alphabet::find_position(cc);
            match tpos {
                Some(ci) => {
                    //Get the key character at position i
                    if let Some(kc) = keystream.chars().nth(i) {
                        //Get position of character within the alphabet
                        if let Some(ki) = alphabet::find_position(kc) {
                            //Calculate the index and retrieve the letter to substitute
                            let si = alphabet::modulo(ci as isize - ki as isize);

                            //We can safely unwrap as we know the index will be within the alphabet
                            let s = alphabet::get_letter(si, cc.is_uppercase()).unwrap();

                            //Push to the decrypted text AND the keystream
                            plaintext.push(s);
                            keystream.push(s);
                        } else {
                            return Err("Keystream contains a non-alphabetic symbol.")
                        }
                    } else {
                        return Err("Keystream is too small for ciphertext length.")
                    }

                },
                None => plaintext.push(cc), //Push non-alphabetic chars 'as-is'
            }
        }

        Ok(plaintext)
    }


    /// Generate an encrypt keystream by concatonating the key and the message itself.
    ///
    /// Will simply return a copy of the key if its length is already larger than the message.
    fn encrypt_keystream(&self, message: &str) -> String {
        //The key is large enough for the message already
        if self.key.len() >= message.len() {
            return self.key.clone();
        }

        //Repeat the scrubed message until it (+ the original key), fits the length of the
        //original message
        let scrubbed_msg = alphabet::scrub_text(&message);
        let mut keystream = String::from(self.key.clone());

        keystream.push_str(&iter::repeat(scrubbed_msg.clone())
            .take((message.len() / (self.key.len() + scrubbed_msg.len())) + 1)
            .collect::<String>());

        keystream[0..message.len()].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_corner_test() {
        let message = "MEETMEATTHECORNER";
        let v = Autokey::new(String::from("king")).unwrap();
        assert_eq!("WMRZYIEMFLEVHYRGF", v.encrypt(message).unwrap());
    }


    #[test]
    fn encrypt_test() {
        let message = "defend the east wall of the castle";
        let v = Autokey::new(String::from("fortification")).unwrap();
        println!();
        println!("m    : {}", message);
        let c_text = v.encrypt(message).unwrap();
        println!("c    : {}", c_text);

        let p_text = v.decrypt(&c_text).unwrap();
        println!("p    : {}", p_text);
        println!();

        assert_eq!(message, p_text);
    }

    // #[test]
    // fn simple_encrypt_decrypt(){
    //     let message = "I never get any credit";
    //     let v = Autokey::new(String::from("givon")).unwrap();
    //
    //     let c_text = v.encrypt(message).unwrap();
    //     println!("{}", v.fit_key(message));
    //     let p_text = v.decrypt(&c_text).unwrap();
    //
    //     assert_eq!(message, p_text);
    // }

    #[test]
    fn decrypt_test() {
        let ciphertext = "lxfopktmdcgn";
        let v = Autokey::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let v = Autokey::new(String::from("giovan")).unwrap();

        let ciphertext = v.encrypt(message).unwrap();
        let plain_text = v.decrypt(&ciphertext).unwrap();

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

    // //Testing the ability to fit a key
    // #[test]
    // fn fit_smaller_key() {
    //     let message = "We are under seige";
    //     let v = Autokey::new(String::from("lemon")).unwrap();
    //
    //     assert_eq!("lemonWeareundersei", v.fit_key(message));
    // }
    //
    // #[test]
    // fn fit_larger_key() {
    //     let message = "hi";
    //     let v = Autokey::new(String::from("lemon")).unwrap();
    //
    //     assert_eq!("lemon", v.fit_key(message));
    // }
    //
    // #[test]
    // fn fit_with_symbols_in_message() {
    //     let message = "HELP ME NOW! PLS@";
    //     let v = Autokey::new(String::from("FORT")).unwrap();
    //     assert_eq!("FORTHELPMENOWPLSH", v.fit_key(message));
    // }
    //
    // #[test]
    // fn fit_larger_key_with_symbols_in_message(){
    //     let message = "EAST!@NOW";
    //     let v = Autokey::new(String::from("FORTIFICATION")).unwrap();
    //     assert_eq!("FORTIFICATION", v.fit_key(message));
    // }
    //
    // #[test]
    // fn fit_key_with_emoji_in_message(){
    //     let message = "Attack🗡 now";
    //     println!("len: {}", message.len());
    //     let v = Autokey::new(String::from("knife")).unwrap();
    //     assert_eq!("knifeAttacknow", v.fit_key(message));
    // }

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
