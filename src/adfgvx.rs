//! The Polybius square, also known as the Polybius checkerboard, is a device invented by the
//! Ancient Greek historian and scholar Polybius, for fractionating plaintext characters so that
//! they can be represented by a smaller set of symbols.
//!
use std::collections::HashMap;
use common::cipher::Cipher;
use common::alphabet::Alphabet;
use common::{alphabet, keygen, substitute};

/// A Polybius square cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct ADFGVX {
    square: HashMap<String, char>,
    transposition_key: String,
}

impl Cipher for ADFGVX {
    type Key = (String, String);
    type Algorithm = ADFGVX;

    /// Initialise an ADFGVX cipher.
    ///
    /// Much like the polybius square cipher, each part of the `key` is used to initialise parts
    /// of the ADFGVX cipher. The `key` tuple maps to the following `(String, String) = (phase,
    /// transposition_key)`.
    ///
    /// Where ...
    ///
    /// * `phrase` is used to generate an alphanumeric keyed alphabet. It can only contain
    /// characters in the ranges `a-z 0-9`.
    /// * `transposition_key` is used during the columnar transposition step of the cipher. It can
    /// only contain alphabetic characters `a-z`.
    ///
    /// For more information on the polybius square step of the ADFGVX cipher, please see the
    /// documentation in the `polybius` module.
    ///
    /// # Example
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ADFGVX};
    ///
    /// let a = ADFGVX::new((String::from("secret"), String::from("cargo"))).unwrap();
    ///
    /// assert_eq!("EEAC AAazadaebabzdc adaebe EF ADdadagebzdc!",
    ///    a.encrypt("10 Oranges and 2 Apples!").unwrap());
    /// ```
    fn new(key: (String, String)) -> Result<ADFGVX, &'static str> {
        let alphabet_key = keygen::keyed_alphabet(&key.0, alphabet::ALPHANUMERIC, false)?;

        let cols_rows = ['A', 'D', 'F', 'G', 'V', 'X'];
        let square = keygen::polybius_square(&alphabet_key, cols_rows, cols_rows)?;

        //TODO: verify the trans key?

        Ok(ADFGVX {square: square, transposition_key: key.1.to_uppercase()})
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
        let polybius_ctext = substitute::polybius_encrypt(&self.square, message);

        let mut i = 0;
        let mut columns: Vec<(char, Vec<Option<char>>)> = self.transposition_key.chars()
                .into_iter()
                .map(|c| (c, Vec::new()))
                .collect();

        for c in polybius_ctext.chars() {
            columns[i].1.push(Some(c));
            i = (i + 1) % columns.len();
        }

        let mut max_len = None;
        if let Some(longest_v) = columns.iter().max_by_key(|v| v.1.len()) {
            max_len = Some(longest_v.1.len());
        }

        if let Some(max_len) = max_len {
            for &mut (_, ref mut v) in columns.iter_mut(){
                let v_len = v.len();
                v.extend(vec![None; (max_len - v_len)]);
            }
        }


        println!("{:?}", columns);


        Err("")
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

        for c in ciphertext.chars().into_iter() {
            //Determine if the character could potentially be part of a 'polybius sequence' to
            //be decrypted. Only standard alphabetic characters can be part of a valid sequence.
            match alphabet::STANDARD.find_position(c) {
                Some(_) => buffer.push(c),
                None => message.push(c)
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
        let a = ADFGVX::new((String::from("secret"), String::from("cargo"))).unwrap();

        assert!(a.encrypt("attack dawn!").is_ok());
    }

    // #[test]
    // fn encrypt_message() {
    //     //     A B C D E F
    //     //  A| o r 0 a n g
    //     //  B| e 1 b c d f
    //     //  C| 2 h i j k 3
    //     //  D| l m p 4 q s
    //     //  E| 5 t u 6 v w
    //     //  F| 7 x 8 y 9 z
    //     let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
    //         ['A','B','C','D','E','F'],
    //         ['A','B','C','D','E','F'])).unwrap();
    //
    //     assert_eq!("BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!",
    //         p.encrypt("10 Oranges and 2 Apples!").unwrap());
    // }
    //
    // #[test]
    // fn decrypt_message() {
    //     let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
    //         ['A','B','C','D','E','F'],
    //         ['A','B','C','D','E','F'])).unwrap();
    //
    //     assert_eq!("10 Oranges and 2 Apples!",
    //         p.decrypt("BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!").unwrap());
    // }
    //
    // #[test]
    // fn invalid_decrypt_sequence() {
    //     let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
    //         ['A','B','C','D','E','F'],
    //         ['A','B','C','D','E','F'])).unwrap();
    //
    //     //The sequnce 'AZ' is unknown to the polybius square
    //     assert!(p.decrypt("BBAC AZabadaeazbadf adaebe CA ADdcdcdabadf!").is_err());
    // }
    //
    // #[test]
    // fn with_utf8() {
    //     let m = "Attack 🗡️ the east wall";
    //     let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
    //         ['A','B','C','D','E','F'],
    //         ['A','B','C','D','E','F'])).unwrap();
    //
    //     assert_eq!(m, p.decrypt(&p.encrypt(m).unwrap()).unwrap());
    // }
    //
    // #[test]
    // fn invalid_key_phrase(){
    //     assert!(Polybius::new(("F@IL".to_string(),
    //         ['A','B','C','D','E','F'],
    //         ['A','B','C','D','E','F'])).is_err());
    // }
    //
    // #[test]
    // fn invalid_ids(){
    //     assert!(Polybius::new(("oranges".to_string(),
    //         ['A','!','C','D','E','F'],
    //         ['A','B','@','D','E','F'])).is_err());
    // }
    //
    // #[test]
    // fn repeated_ids(){
    //     assert!(Polybius::new(("oranges".to_string(),
    //         ['A','A','C','D','E','F'],
    //         ['A','C','C','D','E','F'])).is_err());
    // }
}
