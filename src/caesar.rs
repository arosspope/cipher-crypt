//! The Caesar cipher is named after Julius Caesar, who used it (allegedy) with a shift of three
//! to protect messages of military significance.
//!
//! As with all single-alphabet substitution ciphers, the Caesar cipher is easily broken
//! and in modern practice offers essentially no communication security.
//!
use common::substitute;
use common::cipher::Cipher;

/// A Caesar cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Caesar {
    shift: usize,
}

impl Cipher for Caesar {
    type Key = usize;
    type Algorithm = Caesar;

    /// Initialise a Caesar cipher given a specific shift value.
    ///
    /// Will return `Err` if the shift value is outside the range `1-26`.
    fn new(shift: usize) -> Result<Caesar, &'static str> {
        if shift >= 1 && shift <= 26 {
            return Ok(Caesar {shift: shift});
        }

        Err("Invalid shift factor. Must be in the range 1-26")
    }

    /// Encrypt a message using a Caesar cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::Cipher;
    /// use cipher_crypt::Caesar;
    ///
    /// let c = Caesar::new(3).unwrap();
    /// assert_eq!("Dwwdfn dw gdzq!", c.encrypt("Attack at dawn!"));
    /// ```
    fn encrypt(&self, message: &str) -> String {
        // Encryption of a letter:
        //         E(x) = (x + n) mod 26
        // Where;  x = position of letter in alphabet
        //         n = shift factor (or key)
        substitute::shift_substitution(message, |idx| (idx + self.shift) % 26)
    }

    /// Decrypt a message using a Caesar cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::Cipher;
    /// use cipher_crypt::Caesar;
    ///
    /// let c = Caesar::new(3).unwrap();
    /// assert_eq!("Attack at dawn!", c.decrypt("Dwwdfn dw gdzq!"));
    /// ```
    fn decrypt(&self, cipher_text: &str) -> String {
        // Decryption of a letter:
        //         D(x) = (x - n) mod 26
        // Where;  x = position of letter in alphabet
        //         n = shift factor (or key)
        let decrypt = |idx| {
            let a: isize = idx as isize - self.shift as isize;
            (((a % 26) + 26) % 26) as usize
            //Rust does not natievly support negative wrap around modulo operations
        };

        substitute::shift_substitution(cipher_text, decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("Cvvcem cv fcyp!", c.encrypt("Attack at dawn!"));
    }

    #[test]
    fn decrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("Attack at dawn!", c.decrypt("Cvvcem cv fcyp!"));
    }

    #[test]
    fn with_emoji(){
        let c = Caesar::new(3).unwrap();
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = c.encrypt(message);
        let decrypted = c.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn exhaustive_encrypt(){
        //Test with every possible shift combination
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        for i in 1..26 {
            let c = Caesar::new(i).unwrap();
            let encrypted = c.encrypt(message);
            let decrypted = c.decrypt(&encrypted);
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn key_to_small() {
        assert!(Caesar::new(0).is_err());
    }

    #[test]
    fn key_to_big() {
        assert!(Caesar::new(27).is_err());
    }
}
