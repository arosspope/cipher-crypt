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
        
        
        // A key of one does not transpose the message, therefore we can return a result here.
        // This also prevents an error, since the expression for 'cycle' in get_table_position()
        // would otherwise evaluate to zero, which then causes problems when used with the modulus
        // operator.
        if self.key == 1 {
            return message.to_string()
        }

        // Create the table that will be used for encryption
        // The form of an entry is (bool, char).
        // The bool determines whether the current entry is being used, and if so
        // the char is part of the plain/cipher text
        let mut table = vec![vec![(false, '.'); message.len()]; self.key];

        for (i, c) in message.chars().enumerate() {
            let (row, col) = self.get_table_position(i);
            // Insert the plaintext letter into the table
            table[row][col] = (true, c);
        }

        // Read the ciphertext row by row
        let mut result = String::new();
        for row in &table {
            for &(is_msg_element, table_element) in row {
                if is_msg_element {
                    result.push(table_element);
                }
            }
        }

        result
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
        

        // A key of one does not transpose the message, therefore we can return a result here.
        // This also prevents an error, since the expression for 'cycle' in get_table_position()
        // would otherwise evaluate to zero, which then causes problems when used with the modulus
        // operator.
        if self.key == 1 {
            return cipher_text.to_string()
        }

        // Create the table that will be used for decryption
        // The form of an entry is (bool, char).
        // The bool determines whether the current entry is being used, and if so
        // the char is part of the plain/cipher text
        let mut table = vec![vec![(false, '.'); cipher_text.len()]; self.key];

        // Find elements in the table that should be filled
        for i in 0..cipher_text.len() {
            let (row, col) = self.get_table_position(i);
            // Fill cell with an arbitrary letter
            table[row][col] = (true, '.');
        }

        // Fill the identified positions in the table with the ciphertext, line by line
        let mut ct_iter = cipher_text.chars();
        for row in table.iter_mut() {
            for entry in row.iter_mut() {
                if entry.0 {
                    *entry = (true, ct_iter.next().unwrap());
                }
            }
        }

        // Read the plaintext in a zigzag
        let mut message = String::new();
        for i in 0..cipher_text.len() {
            let (row, col) = self.get_table_position(i);
            message.push(table[row][col].1);
        }

        message
    }

    /// Returns the row and column that will be occupied in the table for a certain index.
    ///
    /// A tuple of the form (row, column) is returned.
    fn get_table_position(&self, index: usize) -> (usize, usize) {
        let col = index;
        // In the railfence cipher the letters are placed diagonally in a zigzag,
        // so, with a key of 4 say, the row numbers will go
        //      0, 1, 2, 3, 2, 1, 0, 1, 2, 3, 2, 1, 0, ...
        // This repeats with a cycle (or period) given by (2*key - 2)
        //      [0, 1, 2, 3, 2, 1], [0, 1, 2, 3, 2, 1], 0, ...
        // This cycle is always even.
        let cycle = 2 * self.key - 2;
        // For the first half of a cycle, the row is given by the index,
        // but for the second half it decreases and is therefore given by the reverse index,
        // the distance from the end of the cycle.
        let row = if index % cycle <= cycle / 2 {
            index % cycle
        }
        else {
            cycle - index % cycle
        };

        (row, col)
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
