//!
//!
use std::collections::HashMap;
use common::{alphabet, keygen};
use common::alphabet::Alphabet;
use common::cipher::Cipher;

/// A Polybius square cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Polybius {
    square: HashMap<String, char>,
}

impl Cipher for Polybius {
    type Key = (String, [char; 6], [char; 6]);
    type Algorithm = Polybius;

    /// Initialise an Affine cipher given the keys `a` and `b`.
    ///
    fn new(key: (String, [char; 6], [char; 6])) -> Result<Polybius, &'static str> {
        let alphabet_key = keygen::keyed_alphabet(&key.0, alphabet::ALPHANUMERIC, false)?;
        let square = keygen::polybius_square(&alphabet_key, key.1, key.2)?;

        Ok(Polybius {square: square})
    }

    /// Encrypt a message using an Affine cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Affine};
    ///
    /// let a = Affine::new((3, 7)).unwrap();
    /// assert_eq!("Hmmhnl hm qhvu!", a.encrypt("Attack at dawn!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        for c in message.chars() {
            let mut entry = None;

            //Attempt to find what the character will map to in the polybius square
            for (key, val) in self.square.iter() {
                if val == &c {
                    entry = Some(key);
                }
            }

            match entry {
                Some(s) => ciphertext.push_str(s),
                //For unknown characters, just push to the ciphertext 'as-is'
                None => ciphertext.push(c)
            }
        }

        Ok(ciphertext)
    }

    /// Decrypt a message using an Affine cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Affine};
    ///
    /// let a = Affine::new((3, 7)).unwrap();
    /// assert_eq!("Attack at dawn!", a.decrypt("Hmmhnl hm qhvu!").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        //We read the ciphertext two bytes at a time and transpose to the original message by the
        //polybius square
        let mut message = String::new();
        let mut buffer = String::new();

        for c in ciphertext.chars().into_iter() {
            //Determine if the character could potentially be part of a 'polybius sequence' to
            //be decrypted
            match alphabet::ALPHANUMERIC.find_position(c) {
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
        //     A B C D E F
        //  A| o r 0 a n g
        //  B| e 1 b c d f
        //  C| 2 h i j k 3
        //  D| l m p 4 q s
        //  E| 5 t u 6 v w
        //  F| 7 x 8 y 9 z
        let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A','B','C','D','E','F'],
            ['A','B','C','D','E','F'])).unwrap();

        assert_eq!("BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!",
            p.encrypt("10 Oranges and 2 Apples!").unwrap());
    }

    #[test]
    fn decrypt_message() {
        let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A','B','C','D','E','F'],
            ['A','B','C','D','E','F'])).unwrap();

        assert_eq!("10 Oranges and 2 Apples!",
            p.decrypt("BBAC AAabadaeafbadf adaebe CA ADdcdcdabadf!").unwrap());
    }

    #[test]
    fn invalid_decrypt_sequence() {
        let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A','B','C','D','E','F'],
            ['A','B','C','D','E','F'])).unwrap();

        //The sequnce 'AZ' is unknown to the polybius square
        assert!(p.decrypt("BBAC AZabadaeazbadf adaebe CA ADdcdcdabadf!").is_err());
    }

    #[test]
    fn with_utf8() {
        let m = "Attack 🗡️ the east wall";
        let p = Polybius::new(("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z".to_string(),
            ['A','B','C','D','E','F'],
            ['A','B','C','D','E','F'])).unwrap();

        assert_eq!(m, p.decrypt(&p.encrypt(m).unwrap()).unwrap());
    }

    //Should i test keys ....?


    // #[test]
    // fn encrypt_message() {
    //     let a = Affine::new((3, 7)).unwrap();
    //     assert_eq!("Hmmhnl hm qhvu!", a.encrypt("Attack at dawn!").unwrap());
    // }
    //
    // #[test]
    // fn decrypt_message() {
    //     let a = Affine::new((3, 7)).unwrap();
    //     assert_eq!("Attack at dawn!", a.decrypt("Hmmhnl hm qhvu!").unwrap());
    // }
    //
    // #[test]
    // fn with_utf8(){
    //     let a = Affine::new((15, 10)).unwrap();
    //     let message = "Peace ✌️ Freedom and Liberty!";
    //
    //     assert_eq!(message, a.decrypt(&a.encrypt(message).unwrap()).unwrap());
    // }
    //
    // #[test]
    // fn exhaustive_encrypt(){
    //     //Test with every combination of a and b
    //     let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    //
    //     for a in 1..27 {
    //         if gcd(a, 26) > 1 {
    //             continue;
    //         }
    //
    //         for b in 1..27 {
    //             let a = Affine::new((a, b)).unwrap();
    //             assert_eq!(message, a.decrypt(&a.encrypt(message).unwrap()).unwrap());
    //         }
    //     }
    // }
    //
    // #[test]
    // fn valid_key(){
    //     assert!(Affine::new((15, 17)).is_ok());
    // }
    //
    // #[test]
    // fn b_shares_factor(){
    //     assert!(Affine::new((15, 2)).is_ok());
    // }
    //
    // #[test]
    // fn a_shares_factor(){
    //     assert!(Affine::new((2, 15)).is_err());
    // }
    //
    // #[test]
    // fn keys_to_small(){
    //     assert!(Affine::new((0, 10)).is_err());
    // }
    //
    // #[test]
    // fn keys_to_big(){
    //     assert!(Affine::new((30, 51)).is_err());
    // }
}
