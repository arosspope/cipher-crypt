//! ROT13 ("rotate by 13 places"), is a simple implementation of the Caesar cipher. It substitutes
//!a letter with the one 13 places after it in the alphabet.
//!
//! ROT13 is its own inverse. That is, `ROT13(ROT13(message)) = message`.
//!
//! ROT13 is used in online forums as a means of hiding spoilers, punchlines, puzzle solutions,
//!and offensive materials from the casual glance.
use common::alphabet;

/// Encrypt or decrypt a message using the ROT13 substitute cipher.
///
/// # Examples
/// Basic usage:
///
/// ```
/// use cipher_crypt::rot13;
///
/// let m = "I am my own inverse";
/// assert_eq!(m, rot13::apply(&rot13::apply(m)));
/// ```
pub fn apply(message: &str) -> String {
    alphabet::mono_substitute(message, |i| (i + 13) % 26)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_emoji(){
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = apply(message);
        let decrypted = apply(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn alphabet_encrypt(){
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        
        let encrypted = apply(message);
        let decrypted = apply(&encrypted);

        assert_eq!(decrypted, message);
    }
}
