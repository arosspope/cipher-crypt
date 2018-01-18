//! The Columnar cipher is a transposition cipher. In a columnar transposition, the message is
//! written out in rows of a fixed length, and then read out again column by column. The
//! columns are chosen in some scrambled order.
//!
//! Columnar transposition continued to be used for serious purposes as a component of more
//! complex ciphers at least into the 1950s.
use common::cipher::Cipher;
use common::{keygen, alphabet};
use common::alphabet::Alphabet;

/// A ColumnarTransposition cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct ColumnarTransposition {
    key: String,
}

impl Cipher for ColumnarTransposition {
    type Key = String;
    type Algorithm = ColumnarTransposition;

    /// Initialize a Columnar Transposition cipher given a specific key.
    ///
    /// Returns `Err` if key is less than or equal to 0.
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `key` length is = 0.
    /// * The `key` contains non-alphanumeric symbols.
    /// * The `key` contains duplicate characters.
    fn new(key: String) -> Result<ColumnarTransposition, &'static str> {
        keygen::columnar_key(&key)?;
        Ok(ColumnarTransposition { key: key })
    }

    /// Encrypt a message with a Columnar Transposition cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let ct = ColumnarTransposition::new(3).unwrap();
    /// assert_eq!("Seeucsprseeartg- esm!", ct.encrypt("Super-secret message!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        //Construct the column
        let mut i = 0;
        let mut chars = message.chars();
        loop {
            if let Some(c) = chars.next() {
                key[i].1.push(c);
            } else if i > 0 {
                key[i].1.push(' '); //We must add padding characters
            } else {
                break;
            }

            i = (i + 1) % key.len();
        }

        //Sort the key based on it's alphabet positions
        key.sort_by(|a, b|
            alphabet::STANDARD.find_position(a.0).unwrap()
            .cmp(&alphabet::STANDARD.find_position(b.0).unwrap())
        );

        //Construct the cipher text
        let mut ciphertext = String::new();
        for column in key.iter() {
            for chr in column.1.iter() {
                ciphertext.push(*chr);
            }
        }

        Ok(ciphertext)
    }

    /// Decrypt a ciphertext with a Columnar Transposition cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let ct = ColumnarTransposition::new(3).unwrap();
    /// assert_eq!("Super-secret message!", ct.decrypt("Seeucsprseeartg- esm!").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        //Sort the key so that it's in its encryption order
        key.sort_by(|a, b|
            alphabet::STANDARD.find_position(a.0).unwrap()
            .cmp(&alphabet::STANDARD.find_position(b.0).unwrap())
        );

        //Transcribe the ciphertext along each column
        let mut chars = ciphertext.chars();
        let col_size: usize = (ciphertext.chars().count() as f32 / self.key.len() as f32).ceil() as usize;

        'outer: for column in &mut key {
            loop {
                if column.1.len() >= col_size {
                    break;
                } else if let Some(c) = chars.next() {
                    column.1.push(c);
                } else {
                    break 'outer; //No more characters left in ciphertext
                }
            }
        }

        let mut plaintext = String::new();
        for i in 0..col_size {
            for chr in self.key.chars(){
                if let Some(column) = key.iter().find(|x| x.0 == chr){
                    plaintext.push(column.1[i]);
                } else {
                    return Err("Could not find column during decryption.");
                }
            }
        }

        Ok(plaintext.trim_right().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple(){
        let message = "wearediscovered";
        let ct = ColumnarTransposition::new(String::from("zebras")).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    // #[test]
    // fn encrypt_fit() {
    //     let message = "attackatdawn";
    //     let ct = ColumnarTransposition::new(6).unwrap();
    //     assert_eq!("atcadwtaktan", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn encrypt_mixed_case_fit() {
    //     let message = "AttackAtDawn";
    //     let ct = ColumnarTransposition::new(6).unwrap();
    //     assert_eq!("AtcADwtaktan", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn encrypt_mixed_case_space_fit() {
    //     let message = "Attack At Dawn";
    //     let ct = ColumnarTransposition::new(7).unwrap();
    //     assert_eq!("Atc tDwtakA an", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn encrypt_notfit() {
    //     let message = "gotellthespartansthouwhopassestby";
    //     let ct = ColumnarTransposition::new(10).unwrap();
    //     assert_eq!("glersupey olsttwas  ttpahhst  ehanoosb  ", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn encrypt_short_key() {
    //     let message = "attackatdawn";
    //     let ct = ColumnarTransposition::new(1).unwrap();
    //     assert_eq!("attackatdawn", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn encrypt_long_key() {
    //     let message = "attackatdawn";
    //     let ct = ColumnarTransposition::new(42).unwrap();
    //     assert_eq!("attackatdawn", ct.encrypt(message).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_fit() {
    //     let ciphertext = "atcadwtaktan";
    //     let ct = ColumnarTransposition::new(6).unwrap();
    //     assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_mixed_case_fit() {
    //     let ciphertext = "AtcADwtaktan";
    //     let ct = ColumnarTransposition::new(6).unwrap();
    //     assert_eq!("AttackAtDawn", ct.decrypt(ciphertext).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_mixed_case_space_fit() {
    //     let ciphertext = "Atc tDwtakA an";
    //     let ct = ColumnarTransposition::new(7).unwrap();
    //     assert_eq!("Attack At Dawn", ct.decrypt(ciphertext).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_notfit() {
    //     let ciphertext = "glersupey olsttwas  ttpahhst  ehanoosb";
    //     let ct = ColumnarTransposition::new(10).unwrap();
    //     assert_eq!("gotellthespartansthouwhopassestby", ct.decrypt(ciphertext).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_short_key() {
    //     let ciphertext = "attackatdawn";
    //     let ct = ColumnarTransposition::new(1).unwrap();
    //     assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    // }
    //
    // #[test]
    // fn decrypt_long_key() {
    //     let ciphertext = "attackatdawn";
    //     let ct = ColumnarTransposition::new(42).unwrap();
    //     assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    // }

    #[test]
    fn with_utf8(){
        let c = ColumnarTransposition::new(String::from("zebras")).unwrap();
        let message = "Peace, Freedom 🗡️ and Liberty!";
        let encrypted = c.encrypt(message).unwrap();
        assert_eq!(c.decrypt(&encrypted).unwrap(), message);
    }

    //TODO: Single Column tests + spaces + trailing spaces
}
