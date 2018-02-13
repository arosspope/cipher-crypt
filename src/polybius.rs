//! The Polybius square, also known as the Polybius checkerboard, is a device invented by the
//! Ancient Greek historian and scholar Polybius, for fractionating plaintext characters so that
//! they can be represented by a smaller set of symbols.
//!
use std::collections::HashMap;
use common::cipher::Cipher;
use common::alphabet::Alphabet;
use common::{alphabet, keygen};

/// A Polybius square cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Polybius {
    square: HashMap<String, char>,
}

impl Cipher for Polybius {
    type Key = (String, [char; 6], [char; 6]);
    type Algorithm = Polybius;

    /// Initialise a Polybius square cipher.
    ///
    /// In this implementation each part of the `key` is used to initialise a 6x6 polybius square.
    /// The `key` tuple maps to the following `(String, [char; 6], [char; 6]) = (phase,
    /// column_ids, row_ids)`.
    ///
    /// Where ...
    ///
    /// * `phrase` is used to generate an alphanumeric keyed alphabet. It can contain characters
    /// `a-z 0-9`.
    /// * `column_ids` are unique identifiers used for each column of the polybius square. Valid
    /// characters are alphabetic only (`a-z`).
    /// * `row_ids` are unique identifiers used for each row of the polybius square. Valid
    /// characters can be alphabetic only (`a-z`).
    ///
    /// # Example
    /// Lets say the phrase was `or0an3ge` the column_ids were `['A','Z','C','D','E','F']`
    /// and the row_ids were `['A','B','G','D','E','F']`. Then the polybius square would look like
    /// ...
    ///
    /// ```md,no_run
    /// __ A Z C D E F
    /// A| o r 0 a n 3
    /// B| g e b c d f
    /// G| h i j k l m
    /// D| p q s t u v
    /// E| w x y z 1 2
    /// F| 4 5 6 7 8 9
    /// ```
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Polybius};
    ///
    /// let p = Polybius::new((String::from("or0an3ge"), ['A','Z','C','D','E','F'],
    ///     ['A','B','G','D','E','F'])).unwrap();
    ///
    /// assert_eq!("EEAC AAazadaebabzdc adaebe EF ADdadagebzdc!",
    ///    p.encrypt("10 Oranges and 2 Apples!").unwrap());
    /// ```
    fn new(key: (String, [char; 6], [char; 6])) -> Result<Polybius, &'static str> {
        let alphabet_key = keygen::keyed_alphabet(&key.0, alphabet::ALPHANUMERIC, false)?;
        let square = keygen::polybius_square(&alphabet_key, key.1, key.2)?;

        Ok(Polybius { square: square })
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
    ///     ['A','B','G','D','E','F'])).unwrap();
    ///
    /// assert_eq!("BCdfdfbcbdgf 🗡️ dfgcbf bfbcbzdf ezbcacac",
    ///    p.encrypt("Attack 🗡️ the east wall").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        for c in message.chars() {
            let mut entry = None;

            //Attempt to find what the character will map to in the polybius square
            for (key, val) in &self.square {
                if val == &c {
                    entry = Some(key);
                }
            }

            match entry {
                Some(s) => ciphertext.push_str(s),
                //For unknown characters, just push to the ciphertext 'as-is'
                None => ciphertext.push(c),
            }
        }

        Ok(ciphertext)
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
    ///     ['A','B','G','D','E','F'])).unwrap();
    ///
    /// assert_eq!("Attack 🗡️ the east wall",
    ///    p.decrypt("BCdfdfbcbdgf 🗡️ dfgcbf bfbcbzdf ezbcacac").unwrap());
    /// ```
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
        )).unwrap();

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
        )).unwrap();

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
        )).unwrap();

        //The sequnce 'AZ' is unknown to the polybius square
        assert!(
            p.decrypt("BBAC AZabadaeazbadf adaebe CA ADdcdcdabadf!")
                .is_err()
        );
    }

    #[test]
    fn with_utf8() {
        let m = "Attack 🗡️ the east wall";
        let p = Polybius::new((
            "or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A', 'B', 'C', 'D', 'E', 'F'],
            ['A', 'B', 'C', 'D', 'E', 'F'],
        )).unwrap();

        assert_eq!(m, p.decrypt(&p.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn invalid_key_phrase() {
        assert!(
            Polybius::new((
                "F@IL".to_string(),
                ['A', 'B', 'C', 'D', 'E', 'F'],
                ['A', 'B', 'C', 'D', 'E', 'F']
            )).is_err()
        );
    }

    #[test]
    fn invalid_ids() {
        assert!(
            Polybius::new((
                "oranges".to_string(),
                ['A', '!', 'C', 'D', 'E', 'F'],
                ['A', 'B', '@', 'D', 'E', 'F']
            )).is_err()
        );
    }

    #[test]
    fn repeated_ids() {
        assert!(
            Polybius::new((
                "oranges".to_string(),
                ['A', 'A', 'C', 'D', 'E', 'F'],
                ['A', 'C', 'C', 'D', 'E', 'F']
            )).is_err()
        );
    }
}
