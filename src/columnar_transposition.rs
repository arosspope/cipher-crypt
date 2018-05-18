//! The Columnar cipher is a transposition cipher. In columnar transposition the message is
//! written out in rows of a fixed length, and then transcribed to a message via the columns.
//! The columns are scrambled based on a secret key.
//!
//! Columnar transposition continued to be used as a component of more complex ciphers up
//! until the 1950s.
//!
use common::alphabet::Alphabet;
use common::cipher::Cipher;
use common::{alphabet, keygen};

/// A Columnar Transposition cipher.
/// This struct is created by the `new()` method. See its documentation for more.
pub struct ColumnarTransposition {
    key: String,
    null_char: Option<char>,
}

impl Cipher for ColumnarTransposition {
    type Key = (String, Option<char>);
    type Algorithm = ColumnarTransposition;

    /// Initialize a Columnar Transposition cipher.
    ///
    /// Where...
    ///
    /// * Elements of `key` are used as the column identifiers.
    /// * The optional `null_char` is used to pad messages of uneven length.
    ///
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `key` length is 0.
    /// * The `key` contains non-alphanumeric symbols.
    /// * The `key` contains duplicate characters.
    /// * The `null_char` is a character within the `key`
    ///
    fn new(key: (String, Option<char>)) -> Result<ColumnarTransposition, &'static str> {
        keygen::columnar_key(&key.0)?;

        if let Some(null_char) = key.1 {
            if key.0.contains(null_char) {
                return Err("The `null_char` cannot be be in the keyword.");
            }
        }

        Ok(ColumnarTransposition {
            key: key.0,
            null_char: key.1,
        })
    }

    /// Encrypt a message with a Columnar Transposition cipher.
    ///
    /// All characters (including utf8) can be encrypted during the transposition process.
    /// However, it is important to note that if padding characters are being used (`null_char`),
    /// the user must ensure that the message does not contain these padding characters, otherwise
    /// problems will occur during decryption. For this reason, the function will `Err` if it
    /// detects padding characters in the message to be encrypted.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let key_word = String::from("zebras");
    /// let null_char = None;
    ///
    /// let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
    ///
    /// assert_eq!("respce!uemeers-taSs g", ct.encrypt("Super-secret message!").unwrap());
    /// ```
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        if let Some(null_char) = self.null_char {
            if message.contains(null_char) {
                return Err("Message contains padding characters.");
            }
        }

        let mut key = keygen::columnar_key(&self.key)?;

        //Construct the column
        let mut i = 0;
        let mut chars = message.trim_right().chars(); //Any trailing spaces will be stripped
        loop {
            if let Some(c) = chars.next() {
                key[i].1.push(c);
            } else if i > 0 {
                if let Some(null_char) = self.null_char {
                    key[i].1.push(null_char)
                }
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
    /// let key_word = String::from("zebras");
    /// let null_char = None;
    ///
    /// let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
    /// assert_eq!("Super-secret message!", ct.decrypt("respce!uemeers-taSs g").unwrap());
    /// ```
    /// Using whitespace as null (special case):
    ///  This will strip only trailing whitespace in message during decryption
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ColumnarTransposition};
    ///
    /// let key_word = String::from("zebras");
    /// let null_char = None;
    /// let message = "we are discovered  "; // Only trailing spaces will be stripped
    ///
    /// let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
    ///
    /// assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),"we are discovered");
    /// ```
    ///
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let mut key = keygen::columnar_key(&self.key)?;

        // Transcribe the ciphertext along each column
        let mut chars = ciphertext.chars();
        // We only know the maximum length, as there may be null spaces
        let max_col_size: usize =
            (ciphertext.chars().count() as f32 / self.key.len() as f32).ceil() as usize;

        // Once we know the max col size, we need to fill the columns according to order of the
        // keyword. So, if the keyword is 'zebras' then the largest column is 'z' according to
        // offset size. If keyword_length is 6 and cipher_text is 31 there are 5 columns that are
        // offset.
        let offset = key.len() - (ciphertext.chars().count() % key.len());
        // Now we need to know which columns are offset
        // Create a set of columns that are offset
        // Then: if column !in offset_cols { // do something }
        let mut offset_cols = String::from("");

        // Only do this if we are not using nulls
        if self.null_char.is_none() && offset != key.len() {
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
                        if let Some(null_char) = self.null_char {
                            if c == null_char && !c.is_whitespace() {
                                break;
                            }
                        }
                        plaintext.push(c);
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

        let key_word = String::from("zebras");
        let null_char = Some('\u{0}');
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn simple_no_padding() {
        let message = "wearediscovered";

        let key_word = String::from("zebras");
        let null_char = None;
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();

        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn with_utf8() {
        let message = "Peace, Freedom 🗡️ and Liberty!";

        let key_word = String::from("zebras");
        let null_char = Some('\u{0}');
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
        let encrypted = ct.encrypt(message).unwrap();
        assert_eq!(ct.decrypt(&encrypted).unwrap(), message);
    }

    #[test]
    fn with_utf8_no_padding() {
        let message = "Peace, Freedom 🗡️ and Liberty!";

        let key_word = String::from("zebras");
        let null_char = None;
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
        let encrypted = ct.encrypt(message).unwrap();
        assert_eq!(ct.decrypt(&encrypted).unwrap(), message);
    }

    #[test]
    fn single_column() {
        let message = "we are discovered";

        let key_word = String::from("z");
        let null_char = Some('\u{0}');
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn single_column_no_padding() {
        let message = "we are discovered";

        let key_word = String::from("z");
        let null_char = None;
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();
        assert_eq!(ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(), message);
    }

    #[test]
    fn trailing_spaces() {
        let message = "we are discovered  "; //The trailing spaces will be stripped

        let key_word = String::from("z");
        let null_char = None;
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }

    #[test]
    fn plaintext_containing_padding() {
        let key_word = String::from("zebras");
        let null_char = Some(' ');
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();

        let plain_text = "This will fail because of spaces.";
        assert!(ct.encrypt(plain_text).is_err());
    }

    #[test]
    fn trailing_spaces_no_padding() {
        let message = "we are discovered  "; //The trailing spaces will be stripped

        let key_word = String::from("z");
        let null_char = None;
        let ct = ColumnarTransposition::new((key_word, null_char)).unwrap();

        assert_eq!(
            ct.decrypt(&ct.encrypt(message).unwrap()).unwrap(),
            "we are discovered"
        );
    }

    #[test]
    fn padding_in_key() {
        ColumnarTransposition::new((String::from("zebras"), Some('z'))).is_err();
    }
}
