//! ROT13 ("rotate by 13 places"), is a simple implementation of the Caesar cipher. It substitutes
//! a letter with the one 13 places after it in the alphabet.
//!
//! ROT13 is its own inverse. That is, `ROT13(ROT13(message)) = message`. Due to its simplicity,
//! this module does not implement the `Cipher` trait.
//!
use common::substitute;

/// Encrypt or decrypt a message using the ROT13 substitute cipher.
///
/// # Examples
/// Basic usage:
///
/// ```
/// use cipher_crypt::ROT13;
///
/// let m = "I am my own inverse";
/// assert_eq!(m, ROT13::apply(&ROT13::apply(m).unwrap()).unwrap());
/// ```
pub fn apply(message: &str) -> Result<String, &'static str> {
    substitute::shift_substitution(message, |i| (i + 13) % 26)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_emoji(){
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = apply(message).unwrap();
        let decrypted = apply(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn alphabet_encrypt(){
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let encrypted = apply(message).unwrap();
        let decrypted = apply(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }
}
