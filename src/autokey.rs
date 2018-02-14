//! An autokey cipher (also known as the autoclave cipher) is a cipher which incorporates the
//! message (the plaintext) into the key.
//!
//! For example, say the message was `ATTACK AT DAWN` and the key was `CRYPT` then the calculated
//! keystream would be `CRYPTA TT ACKA`. It was invented by Blaise de Vigenère in 1586, and is
//! generally more secure than the Vigenere cipher.
use common::cipher::Cipher;
use common::{alphabet, substitute};
use common::alphabet::Alphabet;

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
        if key.len() < 1 {
            return Err("Invalid key. It must have at least one character.");
        } else if !alphabet::STANDARD.is_valid(&key) {
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
    /// let a = Autokey::new(String::from("fort")).unwrap();
    /// assert_eq!("Fhktcd 🗡 mhg otzx aade", a.encrypt("Attack 🗡 the east wall").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption of a letter in a message:
        //         Ci = Ek(Mi) = (Mi + Ki) mod 26
        // Where;  Mi = position within the alphabet of ith char in message
        //         Ki = position within the alphabet of ith char in key
        substitute::key_substitution(message, &mut self.encrypt_keystream(message), |mi, ki| {
            alphabet::STANDARD.modulo((mi + ki) as isize)
        })
    }

    /// Decrypt a message using an Autokey cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Autokey};
    ///
    /// let a = Autokey::new(String::from("fort")).unwrap();
    /// assert_eq!("Attack 🗡 the east wall", a.decrypt("Fhktcd 🗡 mhg otzx aade").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        // Decryption of a letter in a message:
        //         Mi = Dk(Ci) = (Ci - Ki) mod 26
        // Where;  Ci = position within the alphabet of ith char in cipher text
        //         Ki = position within the alphabet of ith char in key
        //
        // Please note that the decrypt keystream is generated 'on the fly' whilst the ciphertext
        // is being decrypted.
        self.autokey_decrypt(ciphertext)
    }
}

impl Autokey {
    fn autokey_decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        //As each character of the ciphertext is decrypted, the un-encrypted char is appended
        //to the base key 'keystream', so that it may be used to decrypt the latter part
        //of the ciphertext
        let mut plaintext = String::new();

        //We start the stream with the base key
        let mut keystream: Vec<char> = self.key.clone().chars().collect();

        for cc in ciphertext.chars() {
            //Find the index of the ciphertext character in the alphabet (if it exists in there)
            let pos = alphabet::STANDARD.find_position(cc);
            match pos {
                Some(ci) => {
                    //Get the next key character in the stream (we always read from position 0)
                    if keystream.len() < 1 {
                        return Err(
                            "Keystream is not large enough for full substitution of message",
                        );
                    }

                    let kc = keystream[0];
                    if let Some(ki) = alphabet::STANDARD.find_position(kc) {
                        //Calculate the index and retrieve the letter to substitute
                        let si = alphabet::STANDARD.modulo(ci as isize - ki as isize);

                        //We can safely unwrap as we know the index will be within the alphabet
                        let s = alphabet::STANDARD
                            .get_letter(si, cc.is_uppercase())
                            .unwrap();

                        //Push to the decrypted text AND the keystream
                        plaintext.push(s);
                        keystream.push(s);
                        keystream.remove(0); //We have consumed the keystream chartacter
                    } else {
                        return Err("Keystream contains a non-alphabetic symbol.");
                    }
                }
                None => plaintext.push(cc), //Push non-alphabetic chars 'as-is'
            }
        }

        Ok(plaintext)
    }

    /// Generate an encrypt keystream by concatonating the key and message itself.
    ///
    /// Will simply return a copy of the key if its length is already larger than the message.
    fn encrypt_keystream(&self, message: &str) -> Vec<char> {
        //The key will only be used to encrypt the portion of the message that is alphabetic
        let scrubbed_msg = alphabet::STANDARD.scrub(message);

        //The key is large enough for the message already
        if self.key.len() >= scrubbed_msg.len() {
            return self.key[0..scrubbed_msg.len()].chars().collect();
        }

        //The keystream is simply a concatonation of the base key + the scrubbed message
        let mut keystream = self.key.clone();
        keystream.push_str(&scrubbed_msg);

        keystream[0..scrubbed_msg.len()].chars().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_utf8() {
        let m = "Attack 🗡️ the east wall";
        let a = Autokey::new(String::from("fort")).unwrap();

        assert_eq!(m, a.decrypt(&a.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn simple_encrypt_decrypt_test() {
        let message = "defend the east wall of the castle";
        let v = Autokey::new(String::from("fortification")).unwrap();

        let c_text = v.encrypt(message).unwrap();
        let p_text = v.decrypt(&c_text).unwrap();

        assert_eq!(message, p_text);
    }

    #[test]
    fn decrypt_test() {
        let ciphertext = "lxfopktmdcgn";
        let v = Autokey::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn larger_base_key() {
        let message = "Hello";
        let v = Autokey::new(String::from("fortification")).unwrap();

        assert_eq!(vec!['f', 'o', 'r', 't', 'i'], v.encrypt_keystream(message));
    }

    #[test]
    fn smaller_base_key() {
        let message = "We are under seige";
        let v = Autokey::new(String::from("lemon")).unwrap();

        assert_eq!(
            vec![
                'l', 'e', 'm', 'o', 'n', 'W', 'e', 'a', 'r', 'e', 'u', 'n', 'd', 'e', 'r'
            ],
            v.encrypt_keystream(message)
        );
    }

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
