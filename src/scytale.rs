//! One of the oldest cryptography tools was a scytale, which was used to perform
//! transposition encryption. It consisted of a cylinder with a strip of parchment (containing a
//! message) wound around it.
//!
//! The ancient Greeks used this cipher to communicate during military campaigns. Sender and
//! recipient each had a cylinder of exactly the same radius. The sender wound a narrow ribbon of
//! parchment around their cylinder. Then they wrote on it lengthwise. After the ribbon is unwound,
//! the writing could be read only by a person who had a cylinder of exactly the same
//! circumference.
//!
//! Scytale encryption is only keyed by the number of letters that fit on each roll
//! around the scytale. Therefore, it can be trivially cracked.
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

    /// Initialize a Scytale cipher with a specific cylinder height.
    ///
    /// Will return `Err` if the `key == 0`.
    fn new(key: usize) -> Result<Scytale, &'static str> {
        if key == 0 {
            Err("Invalid key, height cannot be zero.")
        } else {
            Ok(Scytale { height: key })
        }
    }

    /// Encrypt a message using a Scytale cipher.
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
    /// use cipher_crypt::{Cipher, Scytale};
    ///
    /// let s = Scytale::new(6).unwrap();
    /// assert_eq!("Pegr lefoporaryr !", s.encrypt("Prepare for glory!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // In both these cases the message is not altered
        if self.height >= message.chars().count() || self.height == 1 {
            return Ok(message.to_string());
        }

        // Create the smallest table that fits the message
        let width = (message.chars().count() as f64 / self.height as f64).ceil() as usize;
        let mut table = vec![vec![' '; width]; self.height];

        // Iterate over message and insert into the table, along rows
        for (pos, element) in message.chars().enumerate() {
            let col = pos % self.height;
            let row = pos / self.height;

            table[col][row] = element;
        }

        // Traverse each column and construct ciphertext
        let mut ciphertext = String::new();
        for col in 0..self.height {
            for row in 0..width {
                ciphertext.push(table[col][row]);
            }
        }

        Ok(ciphertext)
    }

    /// Decrypt a message using a Scytale cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Scytale};
    ///
    /// let ct = Scytale::new(6).unwrap();
    /// assert_eq!("Prepare for glory!", ct.decrypt("Pegr lefoporaryr !").unwrap());
    /// ```
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        // In both these cases the ciphertext has not been altered
        if self.height >= ciphertext.chars().count() || self.height == 1 {
            return Ok(ciphertext.to_string());
        }

        // Create the smallest table that fits the ciphertext
        let width = (ciphertext.chars().count() as f64 / self.height as f64).ceil() as usize;
        let mut table = vec![vec![' '; width]; self.height];

        // Iterate over ciphertext and insert into the table, along columns
        for (pos, element) in ciphertext.chars().enumerate() {
            let col = pos / width;
            let row = pos % width;

            table[col][row] = element;
        }

        // Traverse each row and construct plaintext
        let mut plaintext = String::new();
        for row in 0..width {
            for col in 0..self.height {
                plaintext.push(table[col][row]);
            }
        }

        //Make sure to strip any padding characters
        Ok(plaintext.trim_right().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_encrypt() {
        let s = Scytale::new(6).unwrap();
        assert_eq!("aatttdaacwkn", s.encrypt("attackatdawn").unwrap());
    }

    #[test]
    fn simple_decrypt() {
        let s = Scytale::new(6).unwrap();
        assert_eq!("attackatdawn", s.decrypt("aatttdaacwkn").unwrap());
    }

    #[test]
    fn padding_required() {
        let s = Scytale::new(5).unwrap();
        let m = "attackatdawn";
        assert_eq!(m, s.decrypt(&s.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn invalid_height() {
        assert!(Scytale::new(0).is_err());
    }

    #[test]
    fn with_utf8() {
        let s = Scytale::new(5).unwrap();
        let m = "Attack 🗡️ at once.";
        assert_eq!(m, s.decrypt(&s.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn with_spaces() {
        //Spaces at the end of a message are not preserved
        let s = Scytale::new(5).unwrap();
        let m = "Attack At Dawn comrades!  ";
        assert_eq!(
            "Attack At Dawn comrades!",
            s.decrypt(&s.encrypt(m).unwrap()).unwrap()
        );
    }

    #[test]
    fn longer_height() {
        let s = Scytale::new(20).unwrap();
        let m = "attackatdawn";
        assert_eq!(m, s.decrypt(&s.encrypt(m).unwrap()).unwrap());
    }
}
