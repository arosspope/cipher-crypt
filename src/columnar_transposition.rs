//! The Columnar cipher is a transposition cipher. In a columnar transposition, the message is
//! written out in rows of a fixed length, and then read out again column by column. The
//! columns are chosen in some scrambled order.
//!
//! Columnar transposition continued to be used for serious purposes as a component of more
//! complex ciphers at least into the 1950s.
use common::cipher::Cipher;
use common::keygen;

/// A ColumnarTransposition cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct ColumnarTransposition {
    height: usize,
}

impl Cipher for ColumnarTransposition {
    type Key = usize;
    type Algorithm = ColumnarTransposition;

    /// Initialize a Columnar Transposition cipher given a specific key (height of the columns).
    /// Note: This cipher will also encrypt spacing.
    ///
    /// Returns `Err` if key is less than or equal to 0.
    fn new(key: usize) -> Result<ColumnarTransposition, &'static str> {
        let s = "thing";
        keygen::columnar_key(s)?;

        if key <= 0 {
            Err("Invalid key. Number of columns to encrypt must be greater than 0.")
        } else {
            Ok(ColumnarTransposition { height: key })
        }
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
    // fn encrypt(&self, message: &str) -> Result<String, &'static str> {
    //     // Encryption process:
    //     //
    //     // - Create a table which is `self.height` high and the width is
    //     //   such that the total number of entries is greater or equal to
    //     //   the length of the message.
    //     // - Write the message row-wise into the table
    //     // - Read the table column-wise as the ciphertext
    //
    //     // The trivial encryption keys are not considered
    //     if self.height >= message.len() || self.height == 1 {
    //         return Ok(message.to_string())
    //     }
    //
    //     // Create the smallest table that fits the message
    //     let width = (message.len() as f64 / self.height as f64).ceil() as usize;
    //     let mut table = vec![vec![' '; width]; self.height];
    //
    //     // Iterate over message and insert into the table, along rows
    //     for (pos, element) in message.chars().enumerate() {
    //         let col = pos % width;
    //         let row = pos / width;
    //
    //         table[row][col] = element;
    //     }
    //     // Iterate over table and create ciphertext, along columns
    //     let mut ciphertext = String::with_capacity(message.len());
    //     for row in 0..width {
    //         for col in 0..self.height {
    //             ciphertext.push(table[col][row]);
    //         }
    //     }
    //
    //     // Return ciphertext
    //     Ok(ciphertext)
    // }

    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let s = "zebras";
        let mut key = keygen::columnar_key(s)?;

        let mut i = 0;
        for chr in message.chars(){
            key[i].1.push(Some(chr));
            i = (i + 1) % key.len();
        }

        key.sort(); //Re-order the columns based on key

        //Construct the cipher text
        let mut ciphertext = String::new();
        for column in key.iter(){
            for e in column.1.iter(){
                ciphertext.push(e.unwrap());
            }
        }

        println!("{}", ciphertext);

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
        // Decryption process:
        //
        // - Create a table which is `self.height` high and the width is
        //   such that the total number of entries is greater or equal to
        //   the length of the message.
        //
        // - Write the ciphertext column-wise into the table
        // - Read the table row-wise as the plaintext

        // The trivial decryption keys are not considered
        if self.height >= ciphertext.len() || self.height == 1 {
            return Ok(ciphertext.to_string())
        }

        // Create the smallest table that fits the ciphertext
        let width = (ciphertext.len() as f64 / self.height as f64).ceil() as usize;
        let mut table = vec![vec![' '; width]; self.height];

        // Iterate over ciphertext and insert into the table, along columns
        for (pos, element) in ciphertext.chars().enumerate() {
            let col = pos / self.height;
            let row = pos % self.height;

            table[row][col] = element;
        }

        // Iterate over table and create plaintext, along rows
        let mut plaintext = String::with_capacity(ciphertext.len());
        for row in table {
            for element in row {
                plaintext.push(element);
            }
        }

        // Return plaintext and trim any tailing whitespace
        Ok(plaintext.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple(){
        let message = "wearediscovered";
        let ct = ColumnarTransposition::new(8).unwrap();

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
        let c = ColumnarTransposition::new(42).unwrap();
        let message = "Peace, Freedom 🗡️ and Liberty!";
        let encrypted = c.encrypt(message).unwrap();
        assert_eq!(c.decrypt(&encrypted).unwrap(), message);
    }
}
