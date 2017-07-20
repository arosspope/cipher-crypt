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
        let mut columns = self.generate_columns();

        let polybius_ctext = substitute::polybius_encrypt(&self.square, message);
        ADFGVX::transpose_to_columns(&mut columns, &polybius_ctext);
        columns.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(ADFGVX::transpose_to_text(&mut columns)) //TODO: THIS STEP IS WRONG
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
        let mut message = String::new();

        //Construct the columns and sort by alphabetical order
        let mut columns = self.generate_columns();
        columns.sort_by(|a, b| a.0.cmp(&b.0));

        ADFGVX::transpose_to_columns(&mut columns, ciphertext);


        //Re-order the columns so that it is back in the order of the transposition key
        self.reorder_to_transposition_key(&mut columns);

        let polybius_sequence = ADFGVX::transpose_to_text(&mut columns);
        println!("{}", polybius_sequence);

        let m = substitute::polybius_decrypt(&self.square, &polybius_sequence).unwrap();

        println!("{}", m);
        Ok(m)
    }
}

impl ADFGVX {
    fn reorder_to_transposition_key(&self, columns: &mut Vec<(char, Vec<Option<char>>)>)
        //-> Result<_, &'static str>
    {
        for (index, column_id) in self.transposition_key.chars().enumerate() {
            if let Some(pos) = columns.iter().position(|v| v.0 == column_id) {
                let column_to_move = columns[pos].clone();
                columns.remove(pos);
                columns.insert(index, column_to_move);
            }

            // match columns.iter().position(|v| v.0 == column_id) {
            //     Some(pos) => {
            //         let column_to_move = columns[pos].clone();
            //         columns.remove(pos);
            //         columns.insert(index, column_to_move);
            //     },
            //     //None => _
            // }
        }
    }

    fn generate_columns(&self) -> Vec<(char, Vec<Option<char>>)> {
        self.transposition_key.chars()
                .into_iter()
                .map(|c| (c, Vec::new()))
                .collect()
    }

    fn transpose_to_columns(columns: &mut Vec<(char, Vec<Option<char>>)>, text: &str) {
        let mut i = 0;
        for c in text.chars() {
            columns[i].1.push(Some(c));
            i = (i + 1) % columns.len();
        }

        ADFGVX::expand_columns(columns);
    }

    fn expand_columns(columns: &mut Vec<(char, Vec<Option<char>>)>) {
        //Expand each column so that it is of a fixed length
        let mut length = None;
        if let Some(longest_v) = columns.iter().max_by_key(|v| v.1.len()) {
            length = Some(longest_v.1.len());
        }

        if let Some(max) = length {
            for &mut (_, ref mut v) in columns.iter_mut(){
                let v_len = v.len();
                v.extend(vec![None; (max - v_len)]);
            }
        }
    }

    fn transpose_to_text2(columns: Vec<(char, Vec<Option<char>>)>) -> String {
        let mut text = String::new();
        let mut i = 0;

        for column in columns.iter() {
            for character in column.1.iter() {
                if let Some(c) = character {

                }
            }
        }

        text
    }

    fn transpose_to_text(columns: &mut Vec<(char, Vec<Option<char>>)>) -> String {
        let mut text = String::new();
        let mut i = 0;


        //While at least one of the columns have not been completely emptied
        while columns.iter().any(|column| column.1.len() > 0) {
            if columns[i].1.len() < 1 {
                i = (i + 1) % columns.len();
                continue; //Skip if already empty
            }

            //If their is a valid char to consume, push it to the transposed text
            if let Some(c) = columns[i].1[0] {
                text.push(c);
            }

            //This character in the column has been consumed, remove, and shuffle to the next.
            columns[i].1.remove(0);
            i = (i + 1) % columns.len();
        }

        text
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let a = ADFGVX::new((String::from("53empb8d4yl9j1w0ci6asogq2kuthzv7fxnr"),
            String::from("cargo"))).unwrap();

        assert_eq!("DGDDFGGVGFGFDGVVVVDVDGDX", a.encrypt("ATTACKATDAWN").unwrap());
    }

    #[test]
    fn decrypt_message() {
        let a = ADFGVX::new((String::from("53empb8d4yl9j1w0ci6asogq2kuthzv7fxnr"),
            String::from("cargo"))).unwrap();

        assert_eq!("ATTACKATDAWN", a.decrypt("DGGVVGGFVDDVDVGDGGDDFFVX").unwrap());
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
