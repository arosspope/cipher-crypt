//! Bacon's cipher or the Baconian cipher is a method of steganography
//! (a method of hiding a secret message as opposed to just a cipher) devised by Francis Bacon in 1605.
//! A message is concealed in the presentation of text, rather than its content.
//!
//! Each character of the message plaintext is encoded as a 5-bit binary,
//!  these are then "hidden" in a decoy message through the use of font variation.
//!
//! This cipher is very easy to crack, once the method of hiding is known, therefore this
//! implementation includes the options to set whether the substitution is distinct for the whole
//! alphabet, or whether it follows the classical method of treating 'I' and 'J', and 'U' and 'V'
//! as interchangeable characters, as would have been the case in Bacon's time.
//!
//! Also, it allows the user to change the underlying binary
//! character choice, this is traditionally 'a' and 'b', but optionally the user can choose any
//! pair of characters.
//!
//! If no concealing text is given and boilerplate of "Loren ipsum..." is used, given the capacity
//! to hide up to a 50 character plaintext.
//!
use std::collections::HashMap;
use std::string::String;
use common::cipher::Cipher;

/// Default decoy plaintext
const DEFAULT_DECOY: &'static str =
    "Lorem ipsum dolor sit amet, ne tamquam eruditi splendide vix. \
     Mea vitae latine philosophia in, et qui gubergren definiebas. \
     Est et debet aliquam. Ei velit augue quo, quod veniam definitionem nam ut.";
/// The default code length
const CODE_LEN: usize = 5;

/// A traditional code set that makes 'J' = 'I' and 'V' = 'U' as they had equivalent value in Bacon's day
lazy_static! {
    static ref TRAD_CODES: HashMap<&'static str, &'static str> = hashmap!{
        "A" => "AAAAA",
        "B" => "AAAAB",
        "C" => "AAABA",
        "D" => "AAABB",
        "E" => "AABAA",
        "F" => "AABAB",
        "G" => "AABBA",
        "H" => "AABBB",
        "I" => "ABAAA",
        "J" => "ABAAA",
        "K" => "ABAAB",
        "L" => "ABABA",
        "M" => "ABABB",
        "N" => "ABBAA",
        "O" => "ABBAB",
        "P" => "ABBBA",
        "Q" => "ABBBB",
        "R" => "BAAAA",
        "S" => "BAAAB",
        "T" => "BAABA",
        "U" => "BAABB",
        "V" => "BAABB",
        "W" => "BABAA",
        "X" => "BABAB",
        "Y" => "BABBA",
        "Z" => "BABBB",
    };
}

/// A distinct code set that covers all of the alphabet
lazy_static! {
    static ref DISTINCT_CODES: HashMap<&'static str, &'static str> = hashmap!{
        "A" => "AAAAA",
        "B" => "AAAAB",
        "C" => "AAABA",
        "D" => "AAABB",
        "E" => "AABAA",
        "F" => "AABAB",
        "G" => "AABBA",
        "H" => "AABBB",
        "I" => "ABAAA",
        "J" => "ABAAB",
        "K" => "ABABA",
        "L" => "ABABB",
        "M" => "ABBAA",
        "N" => "ABBAB",
        "O" => "ABBBA",
        "P" => "ABBBB",
        "Q" => "BAAAA",
        "R" => "BAAAB",
        "S" => "BAABA",
        "T" => "BAABB",
        "U" => "BABAA",
        "V" => "BABAB",
        "W" => "BABBA",
        "X" => "BABBB",
        "Y" => "BBAAA",
        "Z" => "BBAAB"
    };
}

/// A mapping of alphabet to italic UTF-8 italic codes
lazy_static! {
    static ref ITALIC_CODES: HashMap<&'static str, &'static str> = hashmap!{
        // Using Mathematical Italic
        "A" => "\u{1D434}",
        "B" => "\u{1D435}",
        "C" => "\u{1D436}",
        "D" => "\u{1D437}",
        "E" => "\u{1D438}",
        "F" => "\u{1D439}",
        "G" => "\u{1D43a}",
        "H" => "\u{1D43b}",
        "I" => "\u{1D43c}",
        "J" => "\u{1D43d}",
        "K" => "\u{1D43e}",
        "L" => "\u{1D43f}",
        "M" => "\u{1D440}",
        "N" => "\u{1D441}",
        "O" => "\u{1D442}",
        "P" => "\u{1D443}",
        "Q" => "\u{1D444}",
        "R" => "\u{1D445}",
        "S" => "\u{1D446}",
        "T" => "\u{1D447}",
        "U" => "\u{1D448}",
        "V" => "\u{1D449}",
        "W" => "\u{1D44a}",
        "X" => "\u{1D44b}",
        "Y" => "\u{1D44c}",
        "Z" => "\u{1D44d}",
        // Using Mathematical Sans-Serif Italic
        "a" => "\u{1D622}",
        "b" => "\u{1D623}",
        "c" => "\u{1D624}",
        "d" => "\u{1D625}",
        "e" => "\u{1D626}",
        "f" => "\u{1D627}",
        "g" => "\u{1D628}",
        "h" => "\u{1D629}",
        "i" => "\u{1D62a}",
        "j" => "\u{1D62b}",
        "k" => "\u{1D62c}",
        "l" => "\u{1D62d}",
        "m" => "\u{1D62e}",
        "n" => "\u{1D62f}",
        "o" => "\u{1D630}",
        "p" => "\u{1D631}",
        "q" => "\u{1D632}",
        "r" => "\u{1D633}",
        "s" => "\u{1D634}",
        "t" => "\u{1D635}",
        "u" => "\u{1D636}",
        "v" => "\u{1D637}",
        "w" => "\u{1D638}",
        "x" => "\u{1D639}",
        "y" => "\u{1D63a}",
        "z" => "\u{1D63b}"
    };
}

/// Get the code for a given key (source character)
fn get_code(distinct: bool, key: String) -> String {
    let mut code = String::new();
    if distinct {
        if DISTINCT_CODES.contains_key(key.to_uppercase().as_str()) {
            code.push_str(DISTINCT_CODES.get(key.to_uppercase().as_str()).unwrap());
        }
    } else {
        if TRAD_CODES.contains_key(key.to_uppercase().as_str()) {
            code.push_str(TRAD_CODES.get(key.to_uppercase().as_str()).unwrap());
        }
    }

    code
}

/// Gets the key (the source character) for a given cipher text code
fn get_key(distinct: bool, code: &String) -> String {
    let mut key = String::new();

    let codes = if distinct { DISTINCT_CODES.iter() } else { TRAD_CODES.iter() };
    for (_key, val) in codes {
        if val == &code {
            key.push_str(_key);
        }
    }
    key
}

/// This struct is created by the `new()` method. See its documentation for more.
pub struct Baconian {
    distinct: bool,
    decoy_text: String,
}

impl Cipher for Baconian {
    type Key = (bool, Option<String>);
    type Algorithm = Baconian;

    /// Initialise a Baconian cipher
    ///
    /// The `key` tuple maps to the following:
    ///     `(bool, Option<str>) =
    ///         (distinct, decoy_text)`.
    ///
    /// Where ...
    ///
    /// * whether the encoding will be distinct for all alphabetical characters, or classical
    ///     where I, J, U and V are mapped to the same value pairs
    /// * An optional decoy message that will will be used to hide the message -
    ///     default is boilerplate "Lorem ipsum" text.
    ///
    fn new(key: (bool, Option<String>)) -> Result<Baconian, &'static str> {
        Ok(Baconian {
            distinct: key.0,
            decoy_text: key.1.unwrap_or(String::from(DEFAULT_DECOY)),
        })
    }

    /// Encrypt a message using the Baconian cipher
    ///
    /// send in the message to be encrypted,
    ///  - check that against the length of the decoy_text, the decoy_text
    ///  must be at least 4-times as long (each character of message is encoded by
    ///  4 characters)
    /// - slice the decoy_text to right length and make an Vec<String> of four chars
    /// - each character of plaintext is then encoded (aaaa, aaab etc.)
    /// - italicise each occurrance of the binary char, so for 'b' in the decoy_text,
    ///     the final letter of the sequence is italicised.
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut non_alphas = 0; // A counter for non_alphas

        for c in self.decoy_text.chars() {
            if !c.is_alphabetic() { non_alphas += 1; }
        }
        // Check whether the message fits in the decoy
        // Note: that non-alphabetical characters will be skipped.
        if (message.len() * CODE_LEN) > self.decoy_text.len() - non_alphas {
                return Err("Message too long for supplied decoy text.");
        }

        let mut secret = String::new();
        // Iterate through the message encoding each char
        // Ignore non-alphabetical chars
        for c in message.chars() {
            // get code and add to secret
            let mut key = String::new();
            key.push(c);
            secret += &get_code(self.distinct, key);
        }
        println!("Encoded message: {} of length: {}", secret, secret.len());

        // Complex: decoy_slice needs to = secret.len + num_non_alphabetical_chars
        let mut decoy_slice = self.decoy_text.clone();
        let mut alphas = 0;
        non_alphas = 0;
        for c in self.decoy_text.chars() {
            if c.is_alphabetic() { alphas += 1; } else { non_alphas += 1; }
            if alphas == secret.len() { break; }
        }
        decoy_slice.truncate(alphas + non_alphas);
        println! ("Decoy text used: {} of length: {}", decoy_slice, decoy_slice.len());

        let mut decoy_msg = String::new();
        for c in decoy_slice.chars() {
            if c.is_alphabetic() {
                let code = secret.remove(0); // reduce the secret
                if code == 'B' {
                    let italic = ITALIC_CODES.get(c.to_string().as_str());
                    decoy_msg.push_str(italic.unwrap());
                } else {
                    decoy_msg.push(c);
                }
            } else {
                decoy_msg.push(c);
            }
        }

        Ok(decoy_msg)
    }

    /// Decrypt a message that was encrypted with the Baconian cipher
    ///
    ///
    fn decrypt(&self, message: &str) -> Result<String, &'static str> {
        println!("Baconian decrypt");
        let mut plaintext = String::new();
        let mut ciphertext = String::new();
        let mut code = String::new();
        // The message is decoy text
        // Iterate through swapping any alphabetical chars found in the ITALIC_CODES
        // set to be 'B', else 'A', skip anything else.
        for c in message.chars() {
            if c.is_alphabetic() {
                let mut is_code = false;
                for (_key, val) in ITALIC_CODES.iter() {
                    if *val == c.to_string().as_str() {
                        is_code = true;
                        break;
                    }
                }
                if is_code {
                    ciphertext.push('B');
                } else {
                    ciphertext.push('A');
                }
            }
        }
        for c in ciphertext.chars() {
            code.push(c);
            // If we have the right length code
            if code.len() == CODE_LEN {
                // Look up the key from value
                // Now check the state of the encoding
                // if the character is a 'B' then we italicise the output char
                // pop the decoy
                // push into msg
                plaintext += &get_key(self.distinct, &code);
                // Reset
                code.clear();
            }
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new() {
        let b = Baconian::new((None, false, None)).unwrap();
        println!("Created new Baconian");
    }
}
