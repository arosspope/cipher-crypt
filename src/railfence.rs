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
        
        
        // A key of one causes a problem when calculating the cycle later on,
        // so just return the encrypted message now
        if self.key == 1 {
            return message.to_string()
        }

        // Create the table that will be used for encryption
        // The form of an entry is (bool, char).
        // The bool determines whether the current entry is being used, and if so
        // the char is part of the plain/cipher text
        let mut table = vec![vec![(false, 'a'); message.len()]; self.key];

        for (i, c) in message.chars().enumerate() {
            let col = i;
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
            let row = if i % cycle <= cycle / 2 {
                i % cycle
            }
            else {
                cycle - i%cycle
            };

            // Insert the plaintext letter into the table
            table[row][col] = (true, c);
        }

        // Read the ciphertext row by row
        let mut result = String::new();
        for row in &table {
            for entry in row {
                if entry.0 {
                    result.push(entry.1);
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
        

        // A key of one causes a problem when calculating the cycle later on,
        // so just return the decrypted message now
        if self.key == 1 {
            return cipher_text.to_string()
        }

        // Create the table that will be used for decryption
        // The form of an entry is (bool, char).
        // The bool determines whether the current entry is being used, and if so
        // the char is part of the plain/cipher text
        let mut table = vec![vec![(false, 'a'); cipher_text.len()]; self.key];

        // Find elements in the table that should be filled
        for i in 0..cipher_text.len() {
            let col = i;
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
            let row = if i % cycle <= cycle / 2 {
                i % cycle
            }
            else {
                cycle - i%cycle
            };

            // Fill cell with an arbitrary letter
            table[row][col] = (true, 'a');
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
            let col = i;
            let cycle = 2 * self.key - 2;
            let row = if i % cycle <= cycle / 2 {
                i % cycle
            }
            else {
                cycle - i%cycle
            };

            message.push(table[row][col].1);
        }

        message
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let key = 6;
        let message = "attackatdawn";
        let r = Railfence::new(key).unwrap();
        assert_eq!("awtantdatcak", r.encrypt(message));
    }

    #[test]
    fn encrypt_mixed_case() {
        let key = 3;
        let message = "Hello, World!";
        let r = Railfence::new(key).unwrap();
        assert_eq!("Hoo!el,Wrdl l", r.encrypt(message));
    }

    #[test]
    fn encrypt_short_key() {
        let key = 1;
        let message = "attackatdawn";
        let r = Railfence::new(key).unwrap();
        assert_eq!("attackatdawn", r.encrypt(message));
    }

    #[test]
    fn encrypt_long_key() {
        let key = 20;
        let message = "attackatdawn";
        let r = Railfence::new(key).unwrap();
        assert_eq!("attackatdawn", r.encrypt(message));
    }

    #[test]
    fn decrypt_test() {
        let key = 6;
        let message = "awtantdatcak";
        let r = Railfence::new(key).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    fn decrypt_short_key() {
        let key = 1;
        let message = "attackatdawn";
        let r = Railfence::new(key).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    fn decrypt_mixed_case() {
        let key = 3;
        let message = "Hoo!el,Wrdl l";
        let r = Railfence::new(key).unwrap();
        assert_eq!("Hello, World!", r.decrypt(message));
    }

    #[test]
    fn decrypt_long_key() {
        let key = 20;
        let message = "attackatdawn";
        let r = Railfence::new(key).unwrap();
        assert_eq!("attackatdawn", r.decrypt(message));
    }

    #[test]
    #[should_panic]
    fn incorrect_key_test() {
        let key = 0;
        let r = Railfence::new(key).unwrap();
        r.encrypt("");
    }

    #[test]
    fn unicode_test() {
        let key = 3;
        let r = Railfence::new(key).unwrap();
        let message = "ÂƮƮäƈķ ɑƬ Ðawŋ ✓";
        assert_eq!("ÂƈƬwƮäķɑ aŋ✓Ʈ Ð ", r.encrypt(message));
    }
}
