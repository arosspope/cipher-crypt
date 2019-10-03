//! Homophonic Substitution was an early attempt to make Frequency Analysis a less powerful method 
//! of cryptanalysis. The basic idea behind homophonic substitution is to allocate more than one 
//! letter or symbol to the higher frequency letters. For example, you might use 6 different 
//! symbols to represent "e" and "t", 2 symbols for "m" and 1 symbol for "z".
//!
use crate::common::alphabet::Alphabet;
use crate::common::cipher::Cipher;
use crate::common::{alphabet, keygen};
use std::collections::HashMap;

/// A Homophonic cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Homophonic {
    key: HashMap<char, Vec<char>>,
}

impl Cipher for Homophonic {
    type Key = HashMap<char, Vec<char>>;
    type Algorithm = Homophonic;

    /// Initialise a Homophonic cipher.
    ///
    /// # Panics
    /// * The `key` contains non-alphabetic symbols.
    /// * The `key` is empty.
    ///
    fn new(key: HashMap<char, Vec<char>>) -> Homophonic {
        //

        Homophonic { key }
    }

    /// Encrypt a message using a Polybius square cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Polybius};
    ///
    /// let p = Polybius::new((String::from("p0lyb1us"), ['A','Z','C','D','E','F'],
    ///     ['A','B','G','D','E','F']));;
    ///
    /// assert_eq!("BCdfdfbcbdgf 🗡️ dfgcbf bfbcbzdf ezbcacac",
    ///    p.encrypt("Attack 🗡️ the east wall").unwrap());
    /// ```
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        Ok(message
            .chars()
            .map(|c| {
                if let Some((key, _)) = self.square.iter().find(|e| e.1 == &c) {
                    key.clone()
                } else {
                    c.to_string()
                }
            })
            .collect())
    }

    /// Decrypt a message using a Polybius square cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Polybius};
    ///
    /// let p = Polybius::new((String::from("p0lyb1us"), ['A','Z','C','D','E','F'],
    ///     ['A','B','G','D','E','F']));;
    ///
    /// assert_eq!("Attack 🗡️ the east wall",
    ///    p.decrypt("BCdfdfbcbdgf 🗡️ dfgcbf bfbcbzdf ezbcacac").unwrap());
    /// ```
    ///
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        //We read the ciphertext two bytes at a time and transpose the original message using the
        //polybius square
        let mut message = String::new();
        let mut buffer = String::new();

        for c in ciphertext.chars() {
            //Determine if the character could potentially be part of a 'polybius sequence' to
            //be decrypted. Only standard alphabetic characters can be part of a valid sequence.
            match alphabet::STANDARD.find_position(c) {
                Some(_) => buffer.push(c),
                None => message.push(c),
            }

            if buffer.len() == 2 {
                match self.square.get(&buffer) {
                    Some(&val) => message.push(val),
                    None => return Err("Unknown sequence in the ciphertext."),
                }

                buffer.clear();
            }
        }

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        //     A B C D E F
        //  A| o r 0 a n g
        //  B| e 1 b c d f
        //  C| 2 h i j k 3
        //  D| l m p 4 q s
        //  E| 5 t u 6 v w
        //  F| 7 x 8 y 9 z
        let p = Polybius::new((
            "or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        ));

        assert_eq!(
            "BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!",
            p.encrypt("10 Oranges and 2 Apples!").unwrap()
        );
    }

    #[test]
    fn decrypt_message() {
        let p = Polybius::new((
            "or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        ));

        assert_eq!(
            "10 Oranges and 2 Apples!",
            p.decrypt("BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!")
                .unwrap()
        );
    }

    #[test]
    fn invalid_decrypt_sequence() {
        let p = Polybius::new((
            "or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        ));

        //The sequnce 'AZ' is unknown to the polybius square
        assert!(p
            .decrypt("BBAC AZabadaeazbadf adaebe CA ADdcdcdabadf!")
            .is_err());
    }

    #[test]
    fn with_utf8() {
        let m = "Attack 🗡️ the east wall";
        let p = Polybius::new((
            "or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        ));

        assert_eq!(m, p.decrypt(&p.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    #[should_panic]
    fn invalid_key_phrase() {
        Polybius::new((
            "F@IL".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        ));
    }

    #[test]
    #[should_panic]
    fn invalid_ids() {
        Polybius::new((
            "oranges".to_string(),
            ['A', '!', 'C', 'D', 'E', 'F'],
            ['A', 'B', '@', 'D', 'E', 'F'],
        ));
    }

    #[test]
    #[should_panic]
    fn repeated_ids() {
        Polybius::new((
            "oranges".to_string(),
            ['A', 'A', 'C', 'D', 'E', 'F'],
            ['A', 'C', 'C', 'D', 'E', 'F'],
        ));
    }
}
