//! The Playfair cipher is the first bigram substitution cipher.
//! Invented in 1854 by Charles Wheatstone, its name honors Lord
//! Lyon Playfair for promoting its use.
//!
//! [Reference](https://en.wikipedia.org/wiki/Playfair_cipher)
//!
//! The Playfair cipher operates on a 5x5 table. The key, omitting repeated
//! characters, is written from left to right starting on the first row
//! of the table. Other key layout patterns in the table can be used
//! but are less common. Note that a letter must either be omitted
//! (typically 'Q') or two letters can occupy the same space (I=J).
//! This implementation uses the *latter* design, replacing all
//! encountered 'J' characters with 'I'.
//!
use common::{alphabet, alphabet::Alphabet, cipher::Cipher, keygen::PlayfairTable};

/// The character inserted to avoid repeated characters or
/// to complete an odd-length bigram
const PLAYFAIR_FIX_CHAR: char = 'X';

/// A Playfair cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Playfair {
    /// The Playfair key table (5x5)
    table: PlayfairTable,
}

impl Cipher for Playfair {
    type Key = String;
    type Algorithm = Playfair;

    /// Initialize a Playfair cipher.
    ///
    /// # Warning
    /// * The 5x5 key table requires any 'J' characters in the key
    /// to be substituted with 'I' characters (I = J).
    fn new(key: Self::Key) -> Result<Playfair, &'static str> {
        let key_table = PlayfairTable::new(&key)?;

        Ok(Playfair { table: key_table })
    }

    /// Encrypt a message with the Playfair cipher.
    ///
    /// # Examples
    ///
    /// Basic Usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Playfair};
    ///
    /// let c = Playfair::new("playfair example".to_string()).unwrap();
    /// assert_eq!(
    ///     c.encrypt("Hide the gold in the tree stump").unwrap(),
    ///     "BMODZBXDNABEKUDMUIXMMOUVIF"
    /// );
    /// ```
    ///
    /// # Warning
    /// * The 5x5 key table requires any 'J' characters in the message
    /// to be substituted with 'I' characters (i.e. I = J).
    /// * The resulting ciphertext will be fully uppercase with no whitespace.
    ///
    /// # Errors
    /// * Messages must contain alphabetic characters only.
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let message: String = message.split_whitespace().collect();
        if !alphabet::STANDARD.is_valid(message.as_str()) {
            return Err("Message must only consist of alphabetic characters");
        }

        // Handles Rule 1 (Bigrams)
        let bmsg = bigram(message.to_uppercase())?;

        apply_rules(bmsg, &self.table, |v, first, second| {
            (v[(first + 1) % 5], v[(second + 1) % 5])
        })
    }

    /// Decrypt a message with the Playfair cipher.
    ///
    /// # Examples
    ///
    /// Basic Usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Playfair};
    ///
    /// let c = Playfair::new("playfair example".to_string()).unwrap();
    /// assert_eq!(
    ///     c.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF").unwrap(),
    ///     "HIDETHEGOLDINTHETREXESTUMP"
    /// );
    ///
    /// ```
    ///
    /// # Warning
    /// * The 5x5 key table requires any 'J' characters in the message
    /// to be substituted with 'I' characters (i.e. I = J).
    /// * The resulting plaintext will be fully uppercase with no whitespace.
    /// * The resulting plaintext may contain added 'X' pad characters.
    ///
    /// # Errors
    /// * Messages must contain only alphabetic characters.
    fn decrypt(&self, message: &str) -> Result<String, &'static str> {
        let message: String = message.split_whitespace().collect();
        if !alphabet::STANDARD.is_valid(message.as_str()) {
            return Err("Message must only consist of alphabetic characters");
        }
        // Handles Rule 1
        let bmsg = bigram(message.to_uppercase())?;

        apply_rules(bmsg, &self.table, |v, first, second| {
            (v[(first - 1) % 5], v[(second - 1) % 5])
        })
    }
}

// PLayfair Bigram
type Bigram = (char, char);

/// Apply rule 1 (bigrams).
///
/// # Rule 1
///
/// If both letters are the same (or only one letter is left), add an 'X'
/// after the first letter. Encrypt the new pair and continue. Some variants
/// of Playfair use 'Q' instead of 'X', but any letter, itself uncommon as a
/// repeated pair, will do.
///
/// [Reference](https://en.wikipedia.org/wiki/Playfair_cipher#Description)
///
/// # Errors
/// * Returns an error if the message contains non-alpha characters.
fn bigram<S: AsRef<str>>(message: S) -> Result<Vec<Bigram>, &'static str> {
    if message.as_ref().contains(char::is_whitespace) {
        return Err("Message contains whitespace");
    }
    if !alphabet::STANDARD.is_valid(message.as_ref()) {
        return Err("Message must only consist of alphabetic characters");
    }

    let mut iter = message.as_ref().chars().peekable();
    let mut bigrams: Vec<Bigram> = Vec::new();
    loop {
        let first: char;
        if let Some(x) = iter.next() {
            first = x;
        } else {
            // No characters remaining -- done
            break;
        }

        // Handle repeats
        if let Some(y) = iter.peek() {
            if *y == first {
                bigrams.push((first, PLAYFAIR_FIX_CHAR));
                continue;
            }
        }

        if let Some(y) = iter.next() {
            bigrams.push((first, y));
        } else {
            // Handle odd number of characters
            bigrams.push((first, PLAYFAIR_FIX_CHAR));
        }
    }
    Ok(bigrams)
}

/// Apply rule 2 (Row) or rule 3 (Column).
///
/// # Rule 2
///
/// If the letters appear on the same row of your table, replace them
/// with the letters to their immediate right respectively (wrapping
/// around to the left side of the row if a letter in the original pair
/// was on the right side of the row).
///
/// # Rule 3
///
/// If the letters appear on the same column of your table, replace them
/// with the letters immediately below respectively (wrapping around to the
/// top side of the column if a letter in the original pair was on the
/// bottom side of the column).
///
/// [Reference](https://en.wikipedia.org/wiki/Playfair_cipher#Description)
fn apply_row_col<F>(b: &Bigram, row_col: &[String; 5], shift: &F) -> Option<Bigram>
where
    F: Fn(Vec<char>, usize, usize) -> Bigram,
{
    for rc in row_col.iter() {
        if let Some(first) = rc.find(b.0) {
            if let Some(second) = rc.find(b.1) {
                let v: Vec<char> = rc.chars().collect();
                return Some(shift(v, first, second));
            }
        }
    }
    None
}

/// Identifies 2 corners of the rectangle.
fn find_separate(b: &Bigram, table: &[String; 5]) -> (usize, usize) {
    let mut result = (0, 0);
    for rc in table.iter() {
        if let Some(pos) = rc.find(b.0) {
            result.0 = pos;
            continue;
        }
        if let Some(pos) = rc.find(b.1) {
            result.1 = pos;
            continue;
        }
    }
    result
}

/// Apply rule 4 (Rectangle).
///
/// # Rule 4
///
/// If the letters are not on the same row or column, replace them with
/// the letters on the same row respectively but at the other pair of
/// corners of the rectangle defined by the original pair. The order is
/// important – the first letter of the encrypted pair is the one that
/// lies on the same row as the first letter of the plaintext pair.
///
/// [Reference](https://en.wikipedia.org/wiki/Playfair_cipher#Description)
fn apply_rectangle(b: &Bigram, table: &PlayfairTable) -> Bigram {
    let rows = find_separate(&b, &table.cols);
    let cols = find_separate(&b, &table.rows);

    let row0: Vec<char> = table.rows[rows.0].chars().collect();
    let row1: Vec<char> = table.rows[rows.1].chars().collect();

    (row0[cols.1], row1[cols.0])
}

/// Apply the PlayFair cipher algorithm.
///
/// The operations for encrypt and decrypt are identical
/// except for the direction of the substitution choice.
fn apply_rules<F>(
    bigrams: Vec<Bigram>,
    table: &PlayfairTable,
    shift: F,
) -> Result<String, &'static str>
where
    F: Fn(Vec<char>, usize, usize) -> Bigram,
{
    let mut text = String::new();
    for b in bigrams {
        // Rule 2 (Row)
        if let Some(bigram) = apply_row_col(&b, &table.rows, &shift) {
            text.push(bigram.0);
            text.push(bigram.1);
            continue;
        }

        // Rule 3 (Column)
        if let Some(bigram) = apply_row_col(&b, &table.cols, &shift) {
            text.push(bigram.0);
            text.push(bigram.1);
            continue;
        }

        // Rule 4 (Rectangle)
        let bigram = apply_rectangle(&b, &table);
        text.push(bigram.0);
        text.push(bigram.1);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigram_accepts_alpha_message() {
        assert!(bigram("HelloWorld").is_ok());
    }

    #[test]
    fn bigram_handles_repeats() {
        let message = "FIZZBAR";
        let mut expected: Vec<Bigram> = Vec::new();
        expected.push(('F', 'I'));
        expected.push(('Z', PLAYFAIR_FIX_CHAR));
        expected.push(('Z', 'B'));
        expected.push(('A', 'R'));
        assert!(bigram(message).is_ok());
        assert_eq!(bigram(message).unwrap(), expected);
    }

    #[test]
    fn bigram_handles_odd_length() {
        let message = "WORLD";
        let mut expected: Vec<Bigram> = Vec::new();
        expected.push(('W', 'O'));
        expected.push(('R', 'L'));
        expected.push(('D', PLAYFAIR_FIX_CHAR));
        assert!(bigram(message).is_ok());
        assert_eq!(bigram(message).unwrap(), expected);
    }

    #[test]
    fn bigram_errors_on_spaces() {
        assert!(bigram("Has Spaces").is_err());
    }

    #[test]
    fn bigram_errors_on_nonalpha() {
        assert!(bigram("Bad123").is_err());
    }

    #[test]
    fn cipher_encrypts_std_message() {
        let cipher = Playfair::new("playfair example".to_string()).unwrap();
        assert!(cipher.encrypt("Hide the gold in the tree stump").is_ok());
        assert_eq!(
            cipher.encrypt("Hide the gold in the tree stump").unwrap(),
            "BMODZBXDNABEKUDMUIXMMOUVIF"
        );
    }

    #[test]
    fn cipher_decrypts_std_message() {
        let cipher = Playfair::new("playfair example".to_string()).unwrap();
        assert!(cipher.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF").is_ok());
        assert_eq!(
            cipher.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF").unwrap(),
            "HIDETHEGOLDINTHETREXESTUMP"
        );
    }

    #[test]
    fn new_accepts_alpha_key() {
        assert!(Playfair::new("Foo".to_string()).is_ok());
    }

    #[test]
    fn new_accepts_spaced_key() {
        assert!(Playfair::new("Foo Bar".to_string()).is_ok());
    }

    #[test]
    fn new_rejects_alphanumeric_key() {
        assert!(Playfair::new("Bad123".to_string()).is_err());
    }

    #[test]
    fn new_rejects_symbolic_key() {
        assert!(Playfair::new("Bad?".to_string()).is_err());
    }

    #[test]
    fn new_rejects_unicode_key() {
        assert!(Playfair::new("Bad☢".to_string()).is_err());
    }

    #[test]
    fn encrypt_accepts_spaced_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.encrypt("Bar Baz").is_ok());
    }

    #[test]
    fn encrypt_rejects_alphanumeric_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.encrypt("Bad123").is_err());
    }

    #[test]
    fn encrypt_rejects_symbolic_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.encrypt("Bad?").is_err());
    }

    #[test]
    fn encrypt_rejects_unicode_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.encrypt("Bad☢").is_err());
    }

    #[test]
    fn decrypt_accepts_spaced_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.decrypt("Bar Baz").is_ok());
    }

    #[test]
    fn decrypt_rejects_alphanumeric_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.decrypt("Bad123").is_err());
    }

    #[test]
    fn decrypt_rejects_symbolic_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.decrypt("Bad?").is_err());
    }

    #[test]
    fn decrypt_rejects_unicode_message() {
        let cipher = Playfair::new("Foo".to_string()).unwrap();
        assert!(cipher.decrypt("Bad☢").is_err());
    }
}
