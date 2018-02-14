//! The Columnar cipher is a transposition cipher. In columnar transposition the message is
//! written out in rows of a fixed length, and then transcribed to a message via the columns.
//! The columns are scrambled based on a secret key.
//!
//! Columnar transposition continued to be used as a component of more complex ciphers up
//! until the 1950s.
//!
use common::cipher::Cipher;
use common::{alphabet, keygen};
use common::alphabet::Alphabet;

/// A Columnar Transposition cipher.
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
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `key` length is 0.
    /// * The `key` contains non-alphanumeric symbols.
    /// * The `key` contains duplicate characters.
    fn new(key: String) -> Result<ColumnarTransposition, &'static str> {
        keygen::columnar_key(&key)?;
        Ok(ColumnarTransposition { key: key })
    }

    /// Encrypt a message with a Columnar Transposition cipher.
    ///
    /// Whilst all characters (including utf8) can be encrypted during the transposition process,
    /// it is important to note that the space character is also treated as padding. As such,
    /// whitespace characters at the end of a message are not preserved during the decryption
    /// process.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let ct = ColumnarTransposition::new(String::from("zebras")).unwrap();
    /// assert_eq!("res pce!uemeers -ta Ss g", ct.encrypt("Super-secret message!").unwrap());
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
                // TODO - not sure specification includes padding spaces
                key[i].1.push(' '); //We must add padding characters
            } else {
                break;
            }

            i = (i + 1) % key.len();
        }

        //Sort the key based on it's alphabet positions
        key.sort_by(|a, b| {
            alphabet::STANDARD
                .find_position(a.0)
                .unwrap()
                .cmp(&alphabet::STANDARD.find_position(b.0).unwrap())
        });

        //Construct the cipher text
        let mut ciphertext = String::new();
        for column in &key {
            for chr in &column.1 {
                // TODO: Really need to strip the whitespace
                // and handle the ragged columns in decrypt
                // if !chr.is_whitespace() {
                ciphertext.push(*chr);
                // }
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
    /// let ct = ColumnarTransposition::new(String::from("zebras")).unwrap();
    /// assert_eq!("Super-secret message!", ct.decrypt("res pce!uemeers -ta Ss g").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        //Sort the key so that it's in its encryption order
        key.sort_by(|a, b| {
            alphabet::STANDARD
                .find_position(a.0)
                .unwrap()
                .cmp(&alphabet::STANDARD.find_position(b.0).unwrap())
        });

        //Transcribe the ciphertext along each column
        let mut chars = ciphertext.chars();
        // This will fail as the columns may be differing lengths
        let max_col_size: usize =
            (ciphertext.chars().count() as f32 / self.key.len() as f32).ceil() as usize;

        'outer: for column in &mut key {
            loop {
                if column.1.len() >= max_col_size {
                    break;
                } else if let Some(c) = chars.next() {
                    column.1.push(c);
                } else {
                    break 'outer; //No more characters left in ciphertext
                }
            }
        }

        let mut plaintext = String::new();
        // Okay this can be messy as the columns may be of unequal length
        // Iterate over the headers of the columns
        for i in 0..max_col_size {
            for chr in self.key.chars() {
                if let Some(column) = key.iter().find(|x| x.0 == chr) {
                    // TODO: Fix is the columns are uneven
                    //  Currently breaks the decryption
                    // Also, this breaks when whitespace is added to end of string
                    // if i < column.1.len() {
                    plaintext.push(column.1[i]);
                // }
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
    fn simple() {
        let message = "wearediscovered";
        let ct = ColumnarTransposition::new(String::from("zebras")).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn with_utf8() {
        let c = ColumnarTransposition::new(String::from("zebras")).unwrap();
        let message = "Peace, Freedom 🗡️ and Liberty!";
        let encrypted = c.encrypt(message).unwrap();
        assert_eq!(c.decrypt(&encrypted).unwrap(), message);
    }

    #[test]
    fn single_column() {
        let message = "we are discovered";
        let ct = ColumnarTransposition::new(String::from("z")).unwrap();
        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn trailing_spaces() {
        let message = "we are discovered  "; //The trailing spaces will be stripped
        let ct = ColumnarTransposition::new(String::from("z")).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }
}
