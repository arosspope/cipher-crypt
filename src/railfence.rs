//! The Railfence Cipher is a transposition cipher. It has a very low keyspace and is therefore
//!incredibly insecure.
//!
//! This implementation currently transposes all input characters including whitespace and
//!punctuation.

/// A Railfence cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Railfence {
    key: usize,
}

impl Railfence {
    /// Initialise a Railfence cipher given a specific key.
    ///
    /// Will return `Err` if the key is zero.
    pub fn new(key: usize) -> Result<Railfence, &'static str> {
        if key == 0 {
            return Err("Invalid key. Railfence key cannot be zero.");
        }

        Ok(Railfence { key: key })
    }

    /// Encrypt a message using a Railfence cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::railfence::Railfence;
    ///
    /// let r = Railfence::new(3).unwrap();
    /// assert_eq!("Src s!ue-ertmsaepseeg", r.encrypt("Super-secret message!"));
    /// ```
    pub fn encrypt(&self, message: &str) -> String {
        // Encryption process:
        //   First a table is created with a height given by the key and a length
        //   given by the message length.
        //   e.g.
        //   For a key of 3 and the message "Hello, World!" of length 13:
        //      .............
        //      .............
        //      .............
        //   The message can then be written onto the grid in a zigzag going right:
        //      H...o...o...!
        //      .e.l.,.W.r.d.
        //      ..l... ...l..
        //   The encrypted message is then read line by line:
        //      Hoo!el,Wrdl l

        // We simply return the message as the 'encrypted' message when there is a key of one.
        // This is because one key = one rail in the 'fence'. The message is transposed
        // along this single rail without being altered.
        if self.key == 1 {
            return message.to_string()
        }

        // Initialise the fence (a simple table)
        // The form of an entry is (bool, char) => (is_msg_element, msg_element)
        let mut table = vec![vec![(false, '.'); message.len()]; self.key];

        //Transpose the message along the fence
        for (col, element) in message.chars().enumerate() {
            //Given the column (ith element of the message), determine which row to place the
            //character on
            let row = Railfence::calculate_row(col, self.key);
            table[row][col] = (true, element);
        }

        // Read the ciphertext row by row
        let mut cipher_text = String::new();
        for row in table {
            for (is_msg_element, element) in row {
                if is_msg_element {
                    cipher_text.push(element);
                }
            }
        }

        cipher_text
    }

    /// Decrypt a message using a Railfence cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::railfence::Railfence;
    ///
    /// let r = Railfence::new(3).unwrap();
    /// assert_eq!("Super-secret message!", r.decrypt("Src s!ue-ertmsaepseeg"));
    /// ```
    pub fn decrypt(&self, cipher_text: &str) -> String {
        // Decryption process:
        //   First a table is created with a height given by the key and a length
        //   given by the ciphertext length.
        //   e.g.
        //   For a key of 3 and the ciphertext "Hoo!el,Wrdl l" of length 13:
        //      .............
        //      .............
        //      .............
        //   The positions in the table that would be used to encrypt a message are identified
        //      x...x...x...x
        //      .x.x.x.x.x.x.
        //      ..x...x...x..
        //   The ciphertext is then written onto the indentified positions, line by line
        //      H...o...o...!
        //      .e.l.,.W.r.d.
        //      ..l... ...l..
        //   The decrypted message is then read in a zigzag:
        //      Hello, World!

        // As mentioned previously, a key of one means that the original message has not been
        // altered
        if self.key == 1 {
            return cipher_text.to_string()
        }

        let mut table = vec![vec![(false, '.'); cipher_text.len()]; self.key];

        // Traverse the table and mark the elements that will be filled by the cipher text
        for col in 0..cipher_text.len() {
            let row = Railfence::calculate_row(col, self.key);
            table[row][col].0 = true;
        }

        // Fill the identified positions in the table with the ciphertext, line by line
        let mut ct_chars = cipher_text.chars();
        'outer: for row in table.iter_mut() {
            // For each element in the row, determine if a char should be placed there
            for element in row.iter_mut() {
                if element.0 {
                    if let Some(c) = ct_chars.next() {
                        *element = (element.0, c);
                    } else {
                        // We have transposed all chars of the cipher text
                        break 'outer;
                    }
                }
            }
        }

        // From the transposed cipher text construct the original message
        let mut message = String::new();
        for col in 0..cipher_text.len() {
            // For this column, determine which row we should read from to get the next char
            // of the message
            let row = Railfence::calculate_row(col, self.key);
            message.push(table[row][col].1);
        }

        message
    }

    /// For a given column and the total number of rows, determine the current row that should be
    /// referenced.
    ///
    fn calculate_row(col: usize, total_rows: usize) -> usize {
        // In the railfence cipher the letters are placed diagonally in a zigzag,
        // so, with a key of 4 say, the row numbers will go
        //      0, 1, 2, 3, 2, 1, 0, 1, 2, 3, 2, 1, 0, ...
        // This repeats with a cycle (or period) given by (2*key - 2)
        //      [0, 1, 2, 3, 2, 1], [0, 1, 2, 3, 2, 1], 0, ...
        // This cycle is always even.
        let cycle = 2 * total_rows - 2;

        // For the first half of a cycle, the row is given by the index,
        // but for the second half it decreases and is therefore given by the reverse index,
        // the distance from the end of the cycle.
        let row = if col % cycle <= cycle / 2 {
            col % cycle
        } else {
            cycle - col % cycle
        };

        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "attackatdawn";
        let r = Railfence::new(6).unwrap();
        assert_eq!("awtantdatcak", r.encrypt(message));
    }

    #[test]
    fn encrypt_mixed_case() {
        let message = "Hello, World!";
        let r = Railfence::new(3).unwrap();
        assert_eq!("Hoo!el,Wrdl l", r.encrypt(message));
    }

    #[test]
    fn encrypt_short_key() {
        let message = "attackatdawn";
        let r = Railfence::new(1).unwrap();
        assert_eq!("attackatdawn", r.encrypt(message));
    }

    #[test]
    fn encrypt_long_key() {
        let message = "attackatdawn";
        let r = Railfence::new(20).unwrap();
        assert_eq!("attackatdawn", r.encrypt(message));
    }

    #[test]
    fn decrypt_test() {
        let message = "awtantdatcak";
        let r = Railfence::new(6).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    fn decrypt_short_key() {
        let message = "attackatdawn";
        let r = Railfence::new(1).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    fn decrypt_mixed_case() {
        let message = "Hoo!el,Wrdl l";
        let r = Railfence::new(3).unwrap();
        assert_eq!("Hello, World!", r.decrypt(message));
    }

    #[test]
    fn decrypt_long_key() {
        let message = "attackatdawn";
        let r = Railfence::new(20).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    fn incorrect_key_test() {
        assert!(Railfence::new(0).is_err());
    }

    #[test]
    fn unicode_test() {
        let r = Railfence::new(3).unwrap();
        let message = "ÂƮƮäƈķ ɑƬ Ðawŋ ✓";
        assert_eq!("ÂƈƬwƮäķɑ aŋ✓Ʈ Ð ", r.encrypt(message));
    }
}
