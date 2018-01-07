//! The Scytale cither is said to be used by ancient greeks in general, and Spartans in particular,
//! where a leather or parchment strip is wrapped around a cylinder, called the scytale.
//! After wrapping the strip around the scytale, the message is written horizontally, leaving the
//! message encrypted for anyone reading without the scytale.
//! 
//! Because the scytale encryption is only keyed by the number of letters that fit on each roll
//! around the scytale, meaning it is trivially cracked.
//! 
use common::cipher::Cipher;

/// A Scytale cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Scytale {
    height: usize,
}

impl Cipher for Scytale {
    type Key = usize;
    type Algorithm = Scytale;

    /// Initialize a Scytale cipher with a specified key
    /// which is the height of the columns.
    /// Note: Will also encrypt spacing
    ///
    /// Returns `Err` if the `key == 0`.
    fn new(key: usize) -> Result<Scytale, &'static str> {
        if key == 0 {
            Err("Invalid key, columns cannot be zero characters high")
        } else {
            Ok(Scytale { height: key })
        }
    }

    /// Encrypt a message with a Scytale cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Scytale};
    ///
    /// let ct = Scytale::new(3).unwrap();
    /// assert_eq!("Seeucsprseeartg- esm!", ct.encrypt("Super-secret message!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption process:
        //
        // - Create a table which is `self.height` high and the width is 
        //   such that the total number of entries is greater or equal to
        //   the length of the message.
        //
        // - Write the message row-wise into the table
        // - Read the table column-wise as the ciphertext

        // The trivial encryption keys are not considered
        if self.height >= message.len() || self.height == 1 {
            return Ok(message.to_string())
        }

        // Create the smallest table that fits the message
        let width = (message.len() as f64 / self.height as f64).ceil() as usize;
        let mut table = vec![vec![' '; width]; self.height];

        // Iterate over message and insert into the table, along rows
        for (pos, element) in message.chars().enumerate() {
            let col = pos % width;
            let row = pos / width;

            table[row][col] = element;
        }
        // Iterate over table and create ciphertext, along columns
        let mut ciphertext = String::with_capacity(message.len());
        for row in 0..width {
            for col in 0..self.height {
                ciphertext.push(table[col][row]);
            }
        }

        // Return ciphertext
        Ok(ciphertext)
    }

    /// Decrypt a ciphertext with a Scytale cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Scytale};
    ///
    /// let ct = Scytale::new(3).unwrap();
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

        // Iterate over trable and create plaintext, along rows
        let mut plaintext = String::with_capacity(ciphertext.len());
        for row in table {
            for element in row {
                plaintext.push(element);
            }
        }

        // Return plaintext
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_fit() {
        let message = "attackatdawn";
        let ct = Scytale::new(6).unwrap();
        assert_eq!("atcadwtaktan", ct.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_mixed_case_fit() {
        let message = "AttackAtDawn";
        let ct = Scytale::new(6).unwrap();
        assert_eq!("AtcADwtaktan", ct.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_mixed_case_space_fit() {
        let message = "Attack At Dawn";
        let ct = Scytale::new(7).unwrap();
        assert_eq!("Atc tDwtakA an", ct.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_notfit() {
        let message = "gotellthespartansthouwhopassestby";
        let ct = Scytale::new(10).unwrap();
        assert_eq!("glersupey olsttwas  ttpahhst  ehanoosb  ", ct.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_short_key() {
        let message = "attackatdawn";
        let ct = Scytale::new(1).unwrap();
        assert_eq!("attackatdawn", ct.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_long_key() {
        let message = "attackatdawn";
        let ct = Scytale::new(42).unwrap();
        assert_eq!("attackatdawn", ct.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_fit() {
        let ciphertext = "atcadwtaktan";
        let ct = Scytale::new(6).unwrap();
        assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn decrypt_mixed_case_fit() {
        let ciphertext = "AtcADwtaktan";
        let ct = Scytale::new(6).unwrap();
        assert_eq!("AttackAtDawn", ct.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn decrypt_mixed_case_space_fit() {
        let ciphertext = "Atc tDwtakA an";
        let ct = Scytale::new(7).unwrap();
        assert_eq!("Attack At Dawn", ct.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn decrypt_notfit() {
        let ciphertext = "glersupey olsttwas  ttpahhst  ehanoosb  ";
        let ct = Scytale::new(10).unwrap();
        assert_eq!("gotellthespartansthouwhopassestby       ", ct.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn decrypt_short_key() {
        let ciphertext = "attackatdawn";
        let ct = Scytale::new(1).unwrap();
        assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    }

    #[test]
    fn decrypt_long_key() {
        let ciphertext = "attackatdawn";
        let ct = Scytale::new(42).unwrap();
        assert_eq!("attackatdawn", ct.decrypt(ciphertext).unwrap());
    }
}
