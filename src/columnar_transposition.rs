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
/// This struct is created by the `new()` method. See its documentation for more.
pub struct ColumnarTransposition {
    key: String,
    null_char: char,
    use_nulls: bool,
}

impl Cipher for ColumnarTransposition {
    type Key = (String, String);
    type Algorithm = ColumnarTransposition;

    /// Initialize a Columnar Transposition cipher given:
    /// * a specific `key`, and
    /// * a specified `null` - a character that will pad the columns
    ///
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `key` length is 0.
    /// * The `key` contains non-alphanumeric symbols.
    /// * The `key` contains duplicate characters.
    /// * The `null` contains more than one character
    /// * The `null` contains a character in the `key`
    fn new(key: (String, String)) -> Result<ColumnarTransposition, &'static str> {
        keygen::columnar_key(&key.0)?;

        let mut use_nulls = key.1.len() == 1;
        let mut null_char = '\u{0}'; // Default null

        if use_nulls {
            // Should have an assigned char
            null_char = key.1.chars().next().unwrap();
            // Check the null char is not in the key
            if key.0.contains(null_char) {
                return Err("The `null_char` cannot be be in the keyword.");
            }
        } else if key.1.is_empty() {
            // Will not use
            use_nulls = false;
        } else {
            // Not empty or single character, error!
            return Err("The `null_char` cannot be greater than one char in length.");
        }

        Ok(ColumnarTransposition {
            key: key.0,
            null_char: null_char,
            use_nulls: use_nulls,
        })
    }

    /// Encrypt a message with a Columnar Transposition cipher.
    ///
    /// All characters (including utf8) can be encrypted during the transposition process,
    /// however if the message includes character that are also used as nulls
    /// to pad the columns, `null_char`, then there may be issues with decryption.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let key_word = String::from("zebras");
    /// let null_char = String::from("");
    ///
    /// let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
    ///
    /// assert_eq!("respce!uemeers-taSs g", ct.encrypt("Super-secret message!").unwrap());
    /// ```
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        //Construct the column
        let mut i = 0;
        //  Any trailing spaces will be stripped
        let mut chars = message.trim_right().chars();
        loop {
            if let Some(c) = chars.next() {
                key[i].1.push(c);
            } else if self.use_nulls && i > 0 {
                key[i].1.push(self.null_char);
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
    /// let ct = ColumnarTransposition::new((String::from("zebras"), String::from(""))).unwrap();
    /// assert_eq!("Super-secret message!", ct.decrypt("respce!uemeers-taSs g").unwrap());
    /// ```
    /// Using whitespace as null (special case):
    ///  This will strip only trailing whitespace in message during decryption
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let key_word = String::from("zebras");
    /// let null_char = String::from("");
    /// let message = "we are discovered  "; // Only trailing spaces will be stripped
    ///
    /// let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
    ///
    /// assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),"we are discovered");
    /// ```
    ///
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        //Transcribe the ciphertext along each column
        let mut chars = ciphertext.chars();
        // We only know the maximum length, as there may be null spaces
        let max_col_size: usize =
            (ciphertext.chars().count() as f32 / self.key.len() as f32).ceil() as usize;

        // Once we know the max col size, we need to fill the columns
        // according to order of the keyword
        // So, if the keyword is 'zebras' then the largest column is 'z'
        //  according to offset size
        // So, if keyword_length is 6 and cipher_text is 31 there are 5 columns that are offset
        let offset = key.len() - (ciphertext.chars().count() % key.len());
        // Now we need to know which columns are offset
        // Create a set of columns that are offset
        // Then: if column !in offset_cols { // do something }
        let mut offset_cols = String::from("");

        // Only do this if we are not using nulls
        if !self.use_nulls && offset != key.len() {
            for c in key.clone() {
                offset_cols.push(c.0);
            }
            offset_cols = offset_cols.chars().rev().collect::<String>();
            offset_cols.truncate(offset);
        }

        //Sort the key so that it's in its encryption order
        key.sort_by(|a, b| {
            alphabet::STANDARD
                .find_position(a.0)
                .unwrap()
                .cmp(&alphabet::STANDARD.find_position(b.0).unwrap())
        });

        'outer: for column in &mut key {
            loop {
                let offset_num = if offset_cols.contains(column.0) { 1 } else { 0 };
                // This will test for offset size
                if column.1.len() >= max_col_size - offset_num {
                    break;
                } else if let Some(c) = chars.next() {
                    column.1.push(c);
                } else {
                    break 'outer; //No more characters left in ciphertext
                }
            }
        }

        let mut plaintext = String::new();
        for i in 0..max_col_size {
            for chr in self.key.chars() {
                // Outer getting the key char
                if let Some(column) = key.iter().find(|x| x.0 == chr) {
                    if i < column.1.len() {
                        let c = column.1[i];
                        // Special case for whitespace as the nulls can be trimmed
                        if self.use_nulls && c == self.null_char && !c.is_whitespace() {
                            break;
                        } else {
                            plaintext.push(c);
                        }
                    }
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
        let ct =
            ColumnarTransposition::new((String::from("zebras"), String::from("\u{0}"))).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn simple_no_nulls() {
        let message = "wearediscovered";
        let ct = ColumnarTransposition::new((String::from("zebras"), String::from(""))).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn with_utf8() {
        let c =
            ColumnarTransposition::new((String::from("zebras"), String::from("\u{0}"))).unwrap();
        let message = "Peace, Freedom 🗡️ and Liberty!";
        let encrypted = c.encrypt(message).unwrap();
        assert_eq!(c.decrypt(&encrypted).unwrap(), message);
    }

    #[test]
    fn with_utf8_no_nulls() {
        let c = ColumnarTransposition::new((String::from("zebras"), String::from(""))).unwrap();
        let message = "Peace, Freedom 🗡️ and Liberty!";
        let encrypted = c.encrypt(message).unwrap();
        assert_eq!(c.decrypt(&encrypted).unwrap(), message);
    }

    #[test]
    fn single_column() {
        let message = "we are discovered";
        let ct = ColumnarTransposition::new((String::from("z"), String::from("\u{0}"))).unwrap();
        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn single_column_no_nulls() {
        let message = "we are discovered";
        let ct = ColumnarTransposition::new((String::from("z"), String::from(""))).unwrap();
        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn trailing_spaces() {
        let message = "we are discovered  "; //The trailing spaces will be stripped
        let ct =
            ColumnarTransposition::new((String::from("zebras"), String::from("\u{0}"))).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }

    #[test]
    fn null_as_space() {
        let message = "we are discovered  "; //The trailing spaces will be stripped
        let ct = ColumnarTransposition::new((String::from("z"), String::from(" "))).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }

    #[test]
    fn trailing_spaces_no_nulls() {
        let message = "we are discovered  "; //The trailing spaces will be stripped
        let ct = ColumnarTransposition::new((String::from("z"), String::from(""))).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }

    #[test]
    fn null_too_big() {
        ColumnarTransposition::new((String::from("zebras"), String::from("QW"))).is_err();
    }

    #[test]
    fn null_in_key() {
        ColumnarTransposition::new((String::from("zebras"), String::from("z"))).is_err();
    }
}
